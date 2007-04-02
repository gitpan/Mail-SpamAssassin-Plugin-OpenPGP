# <@LICENSE>
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# </@LICENSE>

package Mail::SpamAssassin::Plugin::OpenPGP;

=head1 NAME

Mail::SpamAssassin::Plugin::OpenPGP - A SpamAssassin plugin that validates OpenPGP signatures.

=head1 VERSION

Version 1.0.0

=cut

our $VERSION = '1.0.0';

#TODO maybe use OpenPGP.pm.PL to generate this file (see perldoc Module::Build "code" section) and include etc/26_openpgp.cf automatically

=head1 SYNOPSIS

Install this module by running:

 cpan Mail::SpamAssassin::Plugin::OpenPGP

Configure SpamAssassin to use it by putting the following (from this module's F<etc/26_openpgp.cf>) in a configuration file (see L<http://wiki.apache.org/spamassassin/WhereDoLocalSettingsGo>)

 loadplugin Mail::SpamAssassin::Plugin::OpenPGP
 
 ifplugin Mail::SpamAssassin::Plugin::OpenPGP
 
 rawbody   OPENPGP_SIGNED     eval:check_openpgp_signed()
 describe OPENPGP_SIGNED     OpenPGP: message body is signed
 
 rawbody   OPENPGP_ENCRYPTED     eval:check_openpgp_encrypted()
 describe OPENPGP_ENCRYPTED     OpenPGP: message body is encrypted
 
 rawbody   OPENPGP_SIGNED_GOOD     eval:check_openpgp_signed_good()
 describe OPENPGP_SIGNED_GOOD     OpenPGP: message body is signed with a valid signature
 tflags nice
 
 rawbody   OPENPGP_SIGNED_BAD     eval:check_openpgp_signed_bad()
 describe OPENPGP_SIGNED_BAD     OpenPGP: message body is signed but the signature is invalid, or doesn't match with email's date or sender
 
 endif   # Mail::SpamAssassin::Plugin::OpenPGP

Set up some rules to your liking, for example:

 score OPENPGP_SIGNED -1
 # this will total to -2
 score OPENPGP_SIGNED_GOOD -1
 # this will total to 0
 score OPENPGP_SIGNED_BAD 1

=head1 DESCRIPTION

This uses Mail::GPG which uses Gnu Privacy Guard

Make sure the homedir you use for gnupg has something like this in its gpg.conf (and that the directory & files are only readable by owner)

 keyserver-options auto-key-retrieve
 # any keyserver will do
 keyserver  x-hkp://random.sks.keyserver.penguin.de

So that it will automatically fetch public keys

To ensure that your local public keys don't get out of date, you should probably set up a scheduled job to delete pubring.gpg regularly

For project information, see L<http://konfidi.org>

=head1 USER SETTINGS

 gpg_executable /path/to/gpg
 gpg_homedir /var/foo/gpg-homedir-for-spamassassin

=cut

=head1 TOKENS

The following per-message SpamAssassin "tokens" are set.  (Is "token" the right word?  They're set directly on instances of PerMsgStatus)

=head2 openpgp_checked

Set to 1 after the email has been checked for an OpenPGP signature

=head2 openpgp_signed

Set to 1 if the email has an OpenPGP signature

=head2 openpgp_signed_good

Set to 1 if the email has a "good" OpenPGP signature

=head2 openpgp_encrypted

Set to 1 if the email is encrypted with OpenPGP

=cut

use warnings;
use strict;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::GPG;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
    my $class = shift;
    my $mailsaobject = shift;

    # some boilerplate...
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);

    dbg "openpgp: created";
    
    $self->register_eval_rule ("check_openpgp_signed");
    $self->register_eval_rule ("check_openpgp_signed_good");
    $self->register_eval_rule ("check_openpgp_signed_bad");
    $self->register_eval_rule ("check_openpgp_encrypted");
    # TODO: trusted none, marginal, full, ultimate

    $self->set_config($mailsaobject->{conf});
    
    return $self;
}

# SA 3.1 style of parsing config options
sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  # see Mail::SpamAssassin::Conf::Parser for expected format of the "config blocks" stored in @cmds

  push(@cmds, {
    setting => 'gpg_homedir', 
    # FIXME: default => 1, 
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
        my ($self, $key, $value, $line) = @_;
        # TODO: validate that it's a directory, writable by only owner
        # TODO: validate that gpg.conf has keyserver and keyserver-options auto-key-retrieve set
        if (0) {
            return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
    },
  });
  push(@cmds, {
    setting => 'gpg_executable', 
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
        my ($self, $key, $value, $line) = @_;
        # TODO: validate that it's an executable
        if (0) {
            return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
    },
  });
  # FIXME do we even need this
  # FIXME use fingerprints, not email address
  push (@cmds, {
    setting => 'whitelist_from_openpgp',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      dbg "openpgp: handling whitelist_from_openpgp";
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      dbg "openpgp: value: $value";
      unless ($value =~ /^(\S+)(?:\s+(\S+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $address = $1;
      dbg "openpgp: address: $address";
      my $signer = (defined $2 ? $2 : $1);
      dbg "openpgp: signer: $signer";

      unless (defined $2) {
        $signer =~ s/^.*@(.*)$/$1/;
      }
      dbg "openpgp: signer: $signer";
      # FIXME use fingerprint
      $self->{parser}->add_to_addrlist_rcvd ('whitelist_from_openpgp', $address, $signer);
    }
  });
  
  # grr, why isn't register_commands documented?
  $conf->{parser}->register_commands(\@cmds);
}

sub check_openpgp_signed_good {
    my ($self, $scan) = @_;
    dbg "openpgp: running check_openpgp_signed_good";
    $self->_check_openpgp($scan);
    return $scan->{openpgp_signed_good};
}
sub check_openpgp_signed_bad {
    my ($self, $scan) = @_;
    dbg "openpgp: running check_openpgp_signed_bad";
    $self->_check_openpgp($scan);
    return $scan->{openpgp_signed} && !$scan->{openpgp_signed_good};
}
sub check_openpgp_signed {
    my ($self, $scan) = @_;
    dbg "openpgp: running check_openpgp_signed";
    $self->_check_openpgp($scan);
    return $scan->{openpgp_signed};
}
sub check_openpgp_encrypted {
    my ($self, $scan) = @_;
    dbg "openpgp: running check_openpgp_encrypted";
    $self->_check_openpgp($scan);
    return $scan->{openpgp_encrypted};
}

# taken from Mail::SpamAssassin::PerMsgStatus's _get
sub _just_email {
    my $result = shift;
    $result =~ s/\s+/ /g;			# reduce whitespace
    $result =~ s/^\s+//;			# leading whitespace
    $result =~ s/\s+$//;			# trailing whitespace

    # Get the email address out of the header
    # All of these should result in "jm@foo":
    # jm@foo
    # jm@foo (Foo Blah)
    # jm@foo, jm@bar
    # display: jm@foo (Foo Blah), jm@bar ;
    # Foo Blah <jm@foo>
    # "Foo Blah" <jm@foo>
    # "'Foo Blah'" <jm@foo>
    # "_$B!z8=6b$=$N>l$GEv$?$j!*!zEv_(B_$B$?$k!*!)$/$8!z7|>^%\%s%P!<!z_(B" <jm@foo>  (bug 3979)
    #
    # strip out the (comments)
    $result =~ s/\s*\(.*?\)//g;
    # strip out the "quoted text"
    $result =~ s/(?<!<)"[^"]*"(?!@)//g;
    # Foo Blah <jm@xxx> or <jm@xxx>
    $result =~ s/^[^<]*?<(.*?)>.*$/$1/;
    # multiple addresses on one line? remove all but first
    $result =~ s/,.*$//;
    return $result;
}

# TODO contribute back to Mail::GPG::Result
sub _gpg_result_date {
    my $result = shift;
    my $gpg_status = $result->get_gpg_status;
    # based on Mail::GPG::Result's analyze_result
    while ( $$gpg_status && $$gpg_status =~ m{^\[GNUPG:\]\s+(.*)$}mg ) {
        my $line = $1;
        if ( $line =~ /^VALIDSIG\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)/ ) {
            #$sign_fingerprint = $1;
            return $3;
        }
    }
}

sub _check_openpgp {
    my ($self, $scan) = @_;
    return if $scan->{openpgp_checked};
    
    $scan->{openpgp_checked} = 0;
    $scan->{openpgp_signed} = 0;
    $scan->{openpgp_signed_good} = 0;
    
    my %opts;
    if (defined $scan->{conf}->{gpg_executable}) {
        $opts{gpg} = $scan->{conf}->{gpg_executable};
    }
    # see GnuPG::Interface's hash_init (correlates to gpg commandline arguments)
    $opts{gnupg_hash_init} = {
        homedir => $scan->{conf}->{gpg_homedir}
    };
    
    my $gpg = Mail::GPG->new(%opts);
    # TODO: use SA-parsed entity instead of having Mail::GPG reparse it into a MIME::Entity?
    my $entity = Mail::GPG->parse(mail_sref => \$scan->{msg}->get_pristine());
    # TODO: configurable option to use is_signed_quick
	if ($gpg->is_signed(entity => $entity)) {
        $scan->{openpgp_signed} = 1;
        dbg "openpgp: is signed";
    }
	if ($gpg->is_encrypted(entity => $entity)) {
        $scan->{openpgp_encrypted} = 1;
        dbg "openpgp: is encrypted";
    }
    
    if ($scan->{openpgp_signed}) {
        my $result = $gpg->verify(entity => $entity); 
        if (!$result->get_is_signed) {
            warn "openpgp: \$gpg->is_signed != \$result->get_is_signed";
            $scan->{openpgp_signed} = 1;
        } else {
            #dbg "openpgp: " . $result->as_string();
            if (${$result->get_gpg_stdout}) {
                dbg "openpgp: gpg stdout:" . ${$result->get_gpg_stdout};
            }
            if (${$result->get_gpg_stderr}) {
                dbg "openpgp: gpg stderr:" . ${$result->get_gpg_stderr};
            }
            if ($result->get_gpg_rc != 0) {
                dbg "openpgp: Error running gpg: " . ${$result->get_gpg_stdout} . ${$result->get_gpg_stderr};
            }
            
            $scan->{openpgp_fingerprint} = $result->get_sign_fingerprint; # TODO if subkey, get master key and use its fingerprint and mail aliases
            $scan->{openpgp_signed_good} = $result->get_sign_ok;
            
            # additional checks if good
            if ($scan->{openpgp_signed_good}) {
                # From address must match one in the public key
                # TODO check 'Sender:' ?
                my $from_email_address = $scan->get('From:addr');
                my $from_ok = 0;
                if ($from_email_address eq _just_email($result->get_sign_mail)) {
                    $from_ok = 1;
                } else {
                    for($result->get_sign_mail_aliases) {
                        if ($from_email_address eq _just_email($_)) {
                            $from_ok = 1;
                            last;
                        }
                    }
                }
                if (!$from_ok) {
                    dbg 'openpgp: from address ' . $from_email_address . ' not in list of email addresses on public key ' . $scan->{openpgp_fingerprint};
                    $scan->{openpgp_signed_good} = 0;
                } else {
                    dbg "openpgp: fingerprint: " . $scan->{openpgp_fingerprint};
                }
            }
            if ($scan->{openpgp_signed_good}) {
                # date of email must be close to that of the signature
                my $sent_date = Mail::SpamAssassin::Util::parse_rfc822_date($scan->get('Date'));
                my $signature_date = _gpg_result_date($result);

                
                # TODO configurable threshold
                my $threshold = 60*60;
                if (abs($sent_date - $signature_date) > $threshold) {
                    dbg "openpgp: mail sent date and signature data are more than $threshold seconds apart: $sent_date $signature_date";
                    $scan->{openpgp_signed_good} = 0;
                }
            }
        }
    }
    
    $scan->{openpgp_checked} = 1;
}

1; # End of Mail::SpamAssassin::Plugin::OpenPGP
__END__

=head1 AUTHOR

Dave Brondsema, C<< <dave at brondsema.net> >>

=head1 BUGS

If an email is signed with a subkey, OPENPGP_SIGNED_BAD is returned.  We need to use the master key's fingerprint and mail aliases instead of the subkey's.

If only part of a PGP/MIME message is signed (for example, a mailing list added a footer outside of the main content & signature) then it is not considered signed.  If any part of a message is signed inline, it is considered signed.
A future version will probably use OPENPGP_PART_SIGNED, and have checks to verify that the unsigned part is at the end and that the signed part is not very short (to prevent spammers from having a small signed part accompanied by a large spammy part).


Please report any bugs or feature requests to
C<bug-mail-spamassassin-plugin-OpenPGP at rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mail-SpamAssassin-Plugin-OpenPGP>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mail::SpamAssassin::Plugin::OpenPGP

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mail-SpamAssassin-Plugin-OpenPGP>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mail-SpamAssassin-Plugin-OpenPGP>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Mail-SpamAssassin-Plugin-OpenPGP>

=item * Search CPAN

L<http://search.cpan.org/dist/Mail-SpamAssassin-Plugin-OpenPGP>

=back

=head1 ACKNOWLEDGEMENTS

=head1 COPYRIGHT & LICENSE

Copyright 2006 Dave Brondsema, all rights reserved.

This program is released under the following license: Apache License, Version 2.0

=cut

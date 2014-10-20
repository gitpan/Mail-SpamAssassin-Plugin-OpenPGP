#!perl

# based on SpamAssassin's own spf.t

use strict;
use warnings;

use lib '.'; use lib 't';
use File::Copy;

# TODO: refactor to NOT use SATest, but something that invokes SA modules directly (not a separate process), so that test coverage can be measured; and to make it much simpler and straightforward (SATest.pm doesn't work the greatest for a 3rd-party module like ours)

# this runs first
sub acceptance_init() {
    diag "Make sure you set environment variable SCRIPT to point to your spamassassin executable (used by SATest.pm)";
    if ($ENV{'SCRIPT'}) {
        diag "Currently, SCRIPT=" . $ENV{'SCRIPT'};
    } else {
        $ENV{'SCRIPT'} = `which spamassassin`;
        chomp $ENV{'SCRIPT'};
        diag "Setting SCRIPT=" . $ENV{'SCRIPT'};
    }
    
    # just to quiet a warning from SATest.pm
    $ENV{'SPAMC_SCRIPT'} =  `which spamc`;
    chomp $ENV{'SPAMC_SCRIPT'};
    
    
    use Test::Harness qw($verbose);
    # only when in verbose mode (e.g. `prove -v ...`, `./Build test verbose=1 ...`)
    if (! $ENV{'SA_ARGS'} and ($ENV{TEST_VERBOSE} or $ENV{HARNESS_VERBOSE} or $verbose)) {
        $ENV{'SA_ARGS'} = '-D openpgp,generic,config,plugin,check,rules';
        diag "Setting SA_ARGS=" . $ENV{'SA_ARGS'};
    }
    
    # SATest.pm expects t/data/01_test_rules.cf
    copy 'etc/26_openpgp.cf', 't/data/01_test_rules.cf' or die "couldn't copy 26_openpgp.cf $!" ;

    sa_t_init("openpgp");
}

sub prep_gpg_home() {
    mkdir('log/gpg-home', 0700);
    open CONF, '>', 'log/gpg-home/gpg.conf';
    print CONF qq{
        keyserver-options auto-key-retrieve
        keyserver  x-hkp://random.sks.keyserver.penguin.de
    };
    close CONF;
    chmod 0600, 'log/gpg-home/gpg.conf';
}

sub acceptance_setup() {
    # add lines to test-local rules
    tstlocalrules (q{
    score OPENPGP_SIGNED -1
    score OPENPGP_SIGNED_GOOD -1
    score OPENPGP_SIGNED_BAD 1
}   );

    prep_gpg_home();

    tstprefs (q{
    dns_available no
    
    #gpg_executable /usr/bin/gpg
    gpg_homedir log/gpg-home
}   );

};

acceptance_init();
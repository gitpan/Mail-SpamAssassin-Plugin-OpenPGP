#!perl
use strict;
use warnings;

use lib '.'; use lib 't';
use SATest;
use Test::More;

require 'acceptance-base.pl';

use constant TEST_ENABLED => conf_bool('run_net_tests');
use constant HAS_GPGCLIENT => eval { require Mail::GPG; };
use constant DO_RUN     => TEST_ENABLED && HAS_GPGCLIENT;

BEGIN {
  plan tests => (DO_RUN ? 8 : 0);
};
exit unless (DO_RUN);

acceptance_setup();

our %patterns = (
    q{ OPENPGP_SIGNED }, 'signed',
    q{ OPENPGP_SIGNED_BAD }, 'signed_bad',
);
our %anti_patterns = ();

sarun("-t < data/expired.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_wrongsender.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_signed_nokeyfound.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/mismatched_time.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern


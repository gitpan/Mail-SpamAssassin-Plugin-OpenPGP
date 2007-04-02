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
  plan tests => (DO_RUN ? 4 : 0);
};
exit unless (DO_RUN);

acceptance_setup();

our %patterns = (
    q{ OPENPGP_ENCRYPTED }, 'encrypted',
);
our %anti_patterns = (
    q{ OPENPGP_SIGNED }, 'signed',
    q{ OPENPGP_SIGNED_BAD }, 'signed_bad',
    q{ OPENPGP_SIGNED_GOOD }, 'signed_good',
);
sarun("-t < data/gpg_encrypted.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern




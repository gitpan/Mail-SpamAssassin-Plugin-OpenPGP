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
  plan tests => (DO_RUN ? 27 : 0);
};
exit unless (DO_RUN);

acceptance_setup();

our %patterns = (
    q{ OPENPGP_SIGNED }, 'signed',
    q{ OPENPGP_SIGNED_GOOD }, 'signed_good',
);
our %anti_patterns = (
    q{ OPENPGP_SIGNED_BAD }, 'signed_bad',
);

sarun("-t < data/gpg_thunderbird.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_evolution.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

# TODO test from EA61 41E8 E49E 560C 224B 2F74 D533 4E75 B131 3DE2, not subkey 8097 6D02 E20C 190B 3AA0 908B 97A3 ADC7 7D0D 4DED
sarun("-t < data/gpg_subkey.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_signed_attachment2.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_signed_binary_attachment.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/gpg_signed_8bit.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

sarun("-t < data/signed_inline.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

# TODO make this OPENPGP_PART_SIGNED
sarun("-t < data/signed_inline_firstpart.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

# TODO make this OPENPGP_PART_SIGNED
sarun("-t < data/signed_inline_secondpart.eml", \&patterns_run_cb);
ok_all_patterns(); # one test per pattern & anti-pattern

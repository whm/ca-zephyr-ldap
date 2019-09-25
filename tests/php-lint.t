#!/usr/bin/perl -w
#
# tests/php-lint.t

use Test::More qw( no_plan );

my $ php_dir = '../usr/share/cz-ldap-monitor/cgi-bin';
opendir (my $dh, $php_dir) or die "Can't open directory $php_dir\n";
while (readdir $dh) {
    my $this_file = $_;
    if ($this_file =~ /[.]php/xms) {
        my $out = `/usr/bin/php -l $php_dir/$this_file 2>&1`;
        ok ($out =~ /^No syntax errors detected/, "lint: $this_file");
        print "$out\n" if $out !~ /^No syntax errors detected/;
    }
}
close $dh;

#!/usr/bin/perl -w
#
# tests/make-ca.t

use Test::More qw( no_plan );

my @script_list = ('usr/bin/ldap-load-config');

for $this_script (@script_list) {
    
    my $s = "../$this_script";

    my $t1 = `$s --help 2>&1`;
    if ($t1 !~ /^Usage/) {
        print "ERROR: $t1\n";
        fail("$s fails Help switch test");
    } else {
        pass("$s Help switch");           
    }
    
    my $t = "${s}.tdy";
    my @cmd = ('perltidy');
    push @cmd, '-bbao';  # put line breaks before any operator
    push @cmd, '-nbbc';  # don't force blank lines before comments
    push @cmd, '-ce';    # cuddle braces around else
    push @cmd, '-l=79';  # don't want 79-long lines reformatted
    push @cmd, '-pt=2';  # don't add extra whitespace around parentheses
    push @cmd, '-sbt=2'; # ...or square brackets
    push @cmd, '-sfs';   # no space before semicolon in for
    push @cmd, $s;
    system(@cmd);

    @cmd = ('diff', '-u', $s, $t);
    if (system(@cmd) == 0) {
        pass("$s is Tidy\n");
    } else {
        fail("$s is UNTIDY\n");
    }
    unlink $t;
}


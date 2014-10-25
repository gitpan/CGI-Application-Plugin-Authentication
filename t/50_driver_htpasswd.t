#!/usr/bin/perl
use Test::More;
use lib qw(t);
eval "use Apache::Htpasswd 1.8;";
plan skip_all => "Apache::Htpasswd >= 1.8 required for this test" if $@;

plan tests => 30;

use strict;
use warnings;

our $HTPASSWD  = 't/htpasswd';
our $HTPASSWD2 = 't/htpasswd2';

{

    package TestAppDriverHTPasswd;

    use base qw(TestAppDriver);

    __PACKAGE__->authen->config(
        DRIVER => [ 'HTPasswd', $HTPASSWD, $HTPASSWD2 ],
        STORE => 'Store::Dummy',
    );

}

TestAppDriverHTPasswd->run_authen_tests(
    [ 'authen_username', 'authen_password' ],
    [ 'user1', '123' ],
    [ 'user2', '123' ],
    [ 'user3', '123' ],
    [ 'user4', '123' ],
    [ 'user5', '123' ],
);


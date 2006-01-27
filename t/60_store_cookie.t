#!/usr/bin/perl
use strict;
use warnings;
use lib qw(t);

use CGI::Util;

use Test::More;

plan tests => 14;

{

    package TestAppStoreCookie;

    use base qw(TestAppStore);

    __PACKAGE__->authen->config(
        DRIVER => [ 'Generic', { 'test' => '123' } ],
        STORE  => [ 'Cookie', SECRET => 'foobar' ],
        CREDENTIALS => [qw(auth_username auth_password)],
    );

    sub get_store_entries {
        my $class = shift;
        my $cgiapp = shift;
        my $results = shift;

        my ($capauth_data) = $results =~ qr/Set\-Cookie:\s+CAPAUTH_DATA=([\d\w%]+);/;
        my $data = CGI::Util::unescape($capauth_data);
        #print STDERR "data:  $data\n" if $data;
        return $data ? $cgiapp->authen->store->_decode($data) : undef;
    }

    sub maintain_state {
        my $class = shift;
        my $old_cgiapp = shift;
        my $old_results = shift;
        my $new_query = shift;

        delete $ENV{'COOKIE'};
        $old_results =~ qr/Set\-Cookie:\s+(CAPAUTH_DATA=[\d\w%]+);/;
        $ENV{'COOKIE'} = $1 if $1;
    }

    sub clear_state {
        my $class = shift;
        delete $ENV{'COOKIE'};
        $class->SUPER::clear_state(@_);
    }

}


TestAppStoreCookie->run_store_tests;



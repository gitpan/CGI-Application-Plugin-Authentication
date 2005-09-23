#!/usr/bin/perl
use Test::More;
eval "use CGI::Application::Plugin::Session";
plan skip_all => "CGI::Application::Plugin::Session required for this test" if $@;

plan tests => 8;

use strict;
use warnings;

use CGI ();

{

    package TestAppAuthenticate;

    use base qw(CGI::Application);
    CGI::Application::Plugin::Session->import; # it was used conditionally above 
    use CGI::Application::Plugin::Authentication;

    __PACKAGE__->authen->config(
        DRIVER => [ 'Generic', { user1 => '123' } ],
        STORE  => 'Session',
    );

    sub setup {
        my $self = shift;
        $self->start_mode('one');
        $self->run_modes([qw(one two)]);
        $self->authen->protected_runmodes(qw(two));
    }

    sub one {
        my $self = shift;
    }

    sub two {
        my $self = shift;
    }
}

$ENV{CGI_APP_RETURN_ONLY} = 1;

# Missing Credentials
my $query =
  CGI->new( { authen_username => 'user1', rm => 'two' } );

my $cgiapp = TestAppAuthenticate->new( QUERY => $query );

my $results = $cgiapp->run;

ok(!$cgiapp->authen->is_authenticated,'missing credentials - login failure');
is( $cgiapp->authen->username, undef, 'missing credentials - username not set' );

# Successful Login
$query =
 CGI->new( { authen_username => 'user1', authen_password => '123', rm => 'two' } );

$cgiapp = TestAppAuthenticate->new( QUERY => $query );
$results = $cgiapp->run;

ok($cgiapp->authen->is_authenticated,'successful login');
is( $cgiapp->authen->username, 'user1', 'successful login - username set' );
is( $cgiapp->authen->login_attempts, 0, "successful login - failed login count" );

# Bad user or password
$query =
 CGI->new( { authen_username => 'user2', authen_password => '123', rm => 'two' } );
$cgiapp = TestAppAuthenticate->new( QUERY => $query );
$results = $cgiapp->run;

ok(!$cgiapp->authen->is_authenticated,'login failure');
is( $cgiapp->authen->username, undef, "login failure - username not set" );
is( $cgiapp->authen->login_attempts, 1, "login failure - failed login count" );


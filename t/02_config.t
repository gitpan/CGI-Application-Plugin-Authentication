#!/usr/bin/perl
use Test::More tests => 45;
use Test::Exception;
use Scalar::Util;
use CGI;
use strict;
use warnings;

{
    package TestAppConfig;

    use base qw(CGI::Application);
    use CGI::Application::Plugin::Authentication;

}


my %config = (
    DRIVER                => [ 'Generic', { user1 => '123', user2 => '123'} ],
    STORE                 => 'Session',
    LOGIN_RUNMODE         => 'login',
    LOGOUT_RUNMODE        => 'logout',
    CREDENTIALS           => ['authen_username', 'authen_password'],
    LOGIN_SESSION_TIMEOUT => '1h',
);
    
my $cgiapp=TestAppConfig->new;
lives_ok { $cgiapp->authen->config(%config) } 'All config parameters accepted';

is_deeply( $cgiapp->authen->credentials,[qw/authen_username authen_password/],'credentials set');
isa_ok($cgiapp->authen->drivers,'CGI::Application::Plugin::Authentication::Driver::Generic');
isa_ok($cgiapp->authen->store,'CGI::Application::Plugin::Authentication::Store::Session');

%config = (
    DRIVER                => [ 'HTPassword', file => 't/htpasswd' ],
    STORE                 => 'Session',
    LOGIN_DESTINATION     => '/login.cgi',
    LOGOUT_DESTINATION    => '/',
    CREDENTIALS           => ['authen_username', 'authen_password'],
    LOGIN_SESSION_TIMEOUT => '1h',
);

lives_ok { TestAppConfig->new->authen->config(%config) } 'All config parameters accepted';

# test DRIVER
throws_ok { TestAppConfig->new->authen->config(DRIVER => { }) } qr/parameter DRIVER is not a string or arrayref/, 'config dies when DRIVER is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(DRIVER => 'MODULE' ) } 'config accepts single DRIVER without options';
lives_ok  { TestAppConfig->new->authen->config(DRIVER => [ 'MODULE', option => 'parameter' ] ) } 'config accepts single DRIVER with options';
lives_ok  { TestAppConfig->new->authen->config(DRIVER => [ [ 'MODULE', option => 'parameter' ], [ 'MODULE', option => 'parameter' ] ] ) } 'config accepts multiple DRIVERs';

# test STORE
throws_ok { TestAppConfig->new->authen->config(STORE => { }) } qr/parameter STORE is not a string or arrayref/, 'config dies when STORE is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(STORE => 'MODULE' ) } 'config accepts STORE without options';
lives_ok  { TestAppConfig->new->authen->config(STORE => [ 'MODULE', option => 'parameter' ] ) } 'config accepts STORE with options';

# test LOGIN_RUNMODE
throws_ok { TestAppConfig->new->authen->config(LOGIN_RUNMODE => { }) } qr/parameter LOGIN_RUNMODE is not a string/, 'config dies when LOGIN_RUNMODE is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(LOGIN_RUNMODE => 'runmode' ) } 'config accepts LOGIN_RUNMODE as a string';

# test LOGIN_DESTINATION
throws_ok { TestAppConfig->new->authen->config(LOGIN_DESTINATION => { }) } qr/parameter LOGIN_DESTINATION is not a string/, 'config dies when LOGIN_DESTINATION is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(LOGIN_DESTINATION => '/' ) } 'config accepts LOGIN_DESTINATION as a string';

# test LOGOUT_RUNMODE
throws_ok { TestAppConfig->new->authen->config(LOGOUT_RUNMODE => { }) } qr/parameter LOGOUT_RUNMODE is not a string/, 'config dies when LOGOUT_RUNMODE is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(LOGOUT_RUNMODE => 'runmode' ) } 'config accepts LOGOUT_RUNMODE as a string';

# test LOGOUT_DESTINATION
throws_ok { TestAppConfig->new->authen->config(LOGOUT_DESTINATION => { }) } qr/parameter LOGOUT_DESTINATION is not a string/, 'config dies when LOGOUT_DESTINATION is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(LOGOUT_DESTINATION => '/' ) } 'config accepts LOGOUT_DESTINATION as a string';

# test CREDENTIALS
throws_ok { TestAppConfig->new->authen->config(CREDENTIALS => { }) } qr/parameter CREDENTIALS is not a string/, 'config dies when CREDENTIALS is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(CREDENTIALS => 'authen_username' ) } 'config accepts CREDENTIALS as a string';
lives_ok  { TestAppConfig->new->authen->config(CREDENTIALS => ['authen_username', 'authen_password'] ) } 'config accepts CREDENTIALS as an arrayref';

# test LOGIN_SESSION_TIMEOUT
throws_ok { TestAppConfig->new->authen->config(LOGIN_SESSION_TIMEOUT => { }) } qr/parameter LOGIN_SESSION_TIMEOUT is not a string/, 'config dies when LOGIN_SESSION_TIMEOUT is passed a hashref';
lives_ok  { TestAppConfig->new->authen->config(LOGIN_SESSION_TIMEOUT => '5h' ) } 'config accepts LOGIN_SESSION_TIMEOUT as a string';
throws_ok { TestAppConfig->new->authen->config(LOGIN_SESSION_TIMEOUT => '5dodgy' ) } qr/parameter LOGIN_SESSION_TIMEOUT is not a valid time string/, 'config dies when LOGIN_SESSION_TIMEOUT recieves an unparsable string';

# authen->config as a class method
lives_ok { TestAppConfig->authen->config(%config) } 'config can be called as a class method';

# authen->config as a class method with hashref
lives_ok { TestAppConfig->authen->config(\%config) } 'config can be called with a hashref or hash';

# authen->config with no parameters
lives_ok { TestAppConfig->authen->config() } 'current configuration returned';

# authen->config dies when passed an invalid parameter
throws_ok { TestAppConfig->new->authen->config(BAD_PARAM => 'foobar' ) } qr/Invalid option\(s\)/, 'config dies when passed an invalid parameter';


# test _time_to_seconds
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10'), 10, "_time_to_seconds works with number only");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10s'), 10, "_time_to_seconds works with seconds");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10m'), 600, "_time_to_seconds works with minutes");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10h'), 36000, "_time_to_seconds works with hours");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10d'), 864000, "_time_to_seconds works with days");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10w'), 6048000, "_time_to_seconds works with weeks");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10M'), 25920000, "_time_to_seconds works with months");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('10y'), 315360000, "_time_to_seconds works with years");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('.5m'), 30, "_time_to_seconds works with decimal values");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('0.5m'), 30, "_time_to_seconds works with decimal values");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('1.5m'), 90, "_time_to_seconds works with decimal values");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('1.m'), 60, "_time_to_seconds works with decimal values");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('1.0m'), 60, "_time_to_seconds works with decimal values");
is(CGI::Application::Plugin::Authentication::_time_to_seconds((1 / 7).'m'), 8, "_time_to_seconds works with decimal value that wouldn't result in an integer offset");
is(CGI::Application::Plugin::Authentication::_time_to_seconds('.5'), undef, "_time_to_seconds fails with decimal values and no modifier");


TODO: {
local $TODO = "TestAppConfig->new->authen->config not finished";


}


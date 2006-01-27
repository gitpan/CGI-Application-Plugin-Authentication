#!/usr/bin/perl
use Test::More;
eval "use CGI::Application::Plugin::Session";
plan skip_all => "CGI::Application::Plugin::Session required for this test" if $@;

plan tests => 2;

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

my $results;
# Missing Credentials
my $query =
  CGI->new( { authen_username => 'user1', rm => 'two' } );

my $cgiapp = TestAppAuthenticate->new( QUERY => $query );

$results = $cgiapp->run;

like($results,qr/document\.loginform\.authen_username/,'default login form');

$cgiapp = TestAppAuthenticate->new( QUERY => $query );
$cgiapp->authen->config(
        DRIVER => [ 'Generic', { user1 => '123' } ],
        STORE  => 'Session',
        RENDER_LOGIN => \&login_view,
      );

$results = $cgiapp->run;

like($results,qr/CUSTOM LOGIN FORM/,'custom login form');

sub login_view {
  my $self = shift;

  return "<html><body>CUSTOM LOGIN FORM</body></html>";
}


#!/usr/bin/perl
use Test::More;
eval "require CGI::Application::Plugin::AutoRunmode";
plan skip_all => "CGI::Application::Plugin::AutoRunmode required for this test" if $@;


use lib './t';
use strict;
use warnings;
use CGI ();

{
    package TestAppAutoRunmode;

    use base qw(CGI::Application);
    use CGI::Application::Plugin::Authentication;
    CGI::Application::Plugin::AutoRunmode->import;
    use Test::More;

    __PACKAGE__->authen->config(
        DRIVER => [ 'Generic', { user1 => '123' } ],
        STORE  => [ 'Cookie', SECRET => 'foobar' ],
    );

    sub setup {
        my $self = shift;
        #$self->start_mode('one');
        #$self->run_modes( [qw(one two three four)] );
        $self->authen->protected_runmodes(qw(two));
    }

    eval <<EOM;
        sub one :StartRunmode { return 'test one return value'; }
        sub two :Runmode { return 'test two return value'; }
        sub three :Runmode :RequireAuthentication { return 'test three return value'; }
        sub four :Runmode :Authen { return 'test four return value'; }
EOM

    plan skip_all => "CGI::Application::Plugin::AutoRunmode version does not work with Authentication" if $@;
}

plan tests => 7;

$ENV{CGI_APP_RETURN_ONLY} = 1;

{
    # Open runmode
    my $query = CGI->new( { rm => 'one' } );
    my $cgiapp = TestAppAutoRunmode->new( QUERY => $query );
    my $results = $cgiapp->run;

    like($results, qr/test one return value/, 'runmode one is open');
}

{
    # Protected runmode (regular)
    my $query = CGI->new( { rm => 'two' } );
    my $cgiapp = TestAppAutoRunmode->new( QUERY => $query );
    my $results = $cgiapp->run;

    unlike($results, qr/test two return value/, 'runmode two is protected');
}

{
    # Protected runmode (attribute RequireAuthentication)
    my $query = CGI->new( { rm => 'three' } );
    my $cgiapp = TestAppAutoRunmode->new( QUERY => $query );
    my $results = $cgiapp->run;

    unlike($results, qr/test three return value/, 'runmode three is protected');
}

{
    # Protected runmode (attribute Authen)
    my $query = CGI->new( { rm => 'four' } );
    my $cgiapp = TestAppAutoRunmode->new( QUERY => $query );
    my $results = $cgiapp->run;

    unlike($results, qr/test four return value/, 'runmode four is protected');
}

{
    # Successful Login
    my $query = CGI->new( { authen_username => 'user1', authen_password => '123', rm => 'three' } );
    my $cgiapp = TestAppAutoRunmode->new( QUERY => $query );
    my $results = $cgiapp->run;

    ok($cgiapp->authen->is_authenticated,'successful login');
    is( $cgiapp->authen->username, 'user1', 'successful login - username set' );
    like($results, qr/test three return value/, 'runmode three is visible after login');
}


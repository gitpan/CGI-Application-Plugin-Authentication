package CGI::Application::Plugin::Authentication;

use strict;
use vars qw($VERSION);
$VERSION = '0.06';

our %__CONFIG;

use Class::ISA ();
use Scalar::Util ();
use UNIVERSAL::require;
use Carp;

sub import {
    my $pkg     = shift;
    my $callpkg = caller;
    {
        no strict qw(refs);
        *{$callpkg.'::authen'} = \&CGI::Application::Plugin::_::Authentication::authen;
    }
    if ( ! UNIVERSAL::isa($callpkg, 'CGI::Application') ) {
        warn "Calling package is not a CGI::Application module so not setting up the prerun hook.  If you are using \@ISA instead of 'use base', make sure it is in a BEGIN { } block, and make sure these statements appear before the plugin is loaded";
    } elsif ( ! UNIVERSAL::can($callpkg, 'add_callback')) {
        warn "You are using an older version of CGI::Application that does not support callbacks, so the prerun method can not be registered automatically (Lookup the prerun_callback method in the docs for more info)";
    } else {
        $callpkg->add_callback( prerun => \&prerun_callback );
    }
}

use Attribute::Handlers;
my %RUNMODES;

sub CGI::Application::RequireAuthentication : ATTR(CODE) {
    my ( $package, $symbol, $referent, $attr, $data, $phase ) = @_;
    $RUNMODES{$referent} = $data || 1;
}
sub CGI::Application::Authen : ATTR(CODE) {
    my ( $package, $symbol, $referent, $attr, $data, $phase ) = @_;
    $RUNMODES{$referent} = $data || 1;
}


=head1 NAME

CGI::Application::Plugin::Authentication - Authentication framework for CGI::Application


=head1 SYNOPSIS

 package MyCGIApp;

 use base qw(CGI::Application); # make sure this occurs before you load the plugin

 use CGI::Application::Plugin::Authentication;

 MyCGIApp->authen->config(
       DRIVER => [ 'Generic', { user1 => '123' } ],
 );
 MyCGIApp->authen->protected_runmodes('myrunmode');

 sub myrunmode {
    my $self = shift;

    # The user should be logged in if we got here
    my $username = $self->authen->username;

 }

=head1 DESCRIPTION

CGI::Application::Plugin::Authentication adds the ability to authenticate users
in your L<CGI::Application> modules.  It imports one method called 'authen' into your
CGI::Application module.  Through the authen method you can call all the methods of
the CGI::Application::Plugin::Authentication plugin.

There are two main decisions that you need to make when using this module.  How will
the usernames and password be verified (ie from a database, LDAP, etc...), and how
can we keep the knowledge that a user has already logged in persistent, so that they
will not have to enter their credentials again on the next request (ie how do we 'Store'
the authentication information across requests).

=head2 Choosing a Driver

There are three drivers that are included with the distribution, and this should actually
be enough to cover everyone's needs.  However, there will be more drivers available on CPAN to
make certain authentication tasks much easier.  Since many people will be authenticating
against a database, a DBI driver is included to cover those needs.  If you need to
authenticate against a different source, you can use the Generic driver which will
accept either a hash of username/password pairs, or an array of arrays of credentials,
or a subroutine reference that can verify the credentials.  So through the Generic
driver you should be able to write your own verification system.  The third Driver is the
Dummy driver, which blindly accepts any credentials.  See the
L<CGI::Application::Plugin::Authentication::Driver::Generic>, 
L<CGI::Application::Plugin::Authentication::Driver::DBI> and, 
L<CGI::Application::Plugin::Authentication::Driver::Dummy> docs for more information
on how to use these drivers.

=head2 Choosing a Store

The Store modules keep information about the authentication status of the user persistent
across multiple requests.  The information that is stored in the store include the username,
and the expiry time of the login.  There are two Store modules included with this distribution.
A Session based store, and a Cookie based store.  If your application is already using
Sessions (through the L<CGI::Application::Plugin::Session> module), then I would recommend
that you use the Session store for authentication.  If you are not using the Session
plugin, then you can use the Cookie store.  The Cookie store keeps all the authentication
in a cookie, which contains a checksum to ensure that users can not change the information.

If you do not specify which Store module you wish to use, the plugin will try to determine
the best one for you.

=head2 Login page

The Authentication plugin comes with a default login page that can be used if you do not
want to create a custom login page.  This login form will automatically be used if you
do not provide either a LOGIN_DESTINATION or LOGIN_RUNMODE parameter in the configuration.
If you plan to create your own login page, I would recommend that you start with the HTML
code for the default login page, so that your login page will contain the correct form
fields and hidden fields.

TODO:  The login page is designed using CSS stylesheets.  I plan to make this more flexible,
so that you can easily create your own stylesheets to make this login form more re-usable.
Also, the default CSS has only really been tested on Mozilla based browser, so if there
are any CSS gurus out there, I would appreciate some help in getting the default login
page to work nicely in most browsers.  Currently it should degrade gracefully, but it
might not be pretty...


=head2 Ticket based authentication

This Authentication plugin can handle ticket based authentication systems as well.  All that
is required of you is to write a Store module that can understand the contents of the ticket.
The Authentication plugin will require at least the 'username' to be retrieved from the
ticket.  A Ticket based authentication scheme will not need a Driver module at all, since the
actual verification of credentials is done by an external authentication system, possibly
even on a different host.  You will need to specify the location of the login page using
the LOGIN_DESTINATION configuration variable, and un-authenticated users will automatically
be redirected to your ticket authentication login page.


=head1 EXPORTED METHODS

=head2 authen

This is the only method exported from this module.  Everything is controlled
through this method call, which will return a CGI::Application::Plugin::Authentication
object, or just the class name if called as a class method.  When using
the plugin, you will always first call $self->authen or __PACKAGE__->authen and
then the method you wish to invoke.  For example:

  __PACKAGE__->authen->config(
        LOGIN_RUNMODE => 'login',
  );

- or -

  $self->authen->protected_runmodes(qw(one two));

=cut


{   package # Hide from PAUSE
        CGI::Application::Plugin::_::Authentication;

    ##############################################
    ###
    ###   authen
    ###
    ##############################################
    #
    # Return an authen object that can be used
    # for managing authentication.
    #
    # This will return a class name if called
    # as a class name, and a singleton object
    # if called as an object method
    #
    sub authen {
        my $cgiapp = shift;

        if (ref($cgiapp)) {
            return CGI::Application::Plugin::Authentication->instance($cgiapp);
        } else {
            return 'CGI::Application::Plugin::Authentication';
        }
    }

}

package CGI::Application::Plugin::Authentication;



=head1 METHODS

=head2 config

This method is used to configure the CGI::Application::Plugin::Authentication
module.  It can be called as an object method, or as a class method.

The following parameters are accepted:

=over 4

=item DRIVER

Here you can choose which authentication module(s) you want to use to perform the authentication.
For simplicity, you can leave off the CGI::Application::Plugin::Authentication::Driver:: part
when specifying the DRIVER name  If this module requires extra parameters, you
can pass an array reference that contains as the first parameter the name of the module,
and the rest of the values in the array will be considered options for the driver.  You can provide
multiple drivers which will be used, in order, to check the credentials until
a valid response is received.

     DRIVER => 'Dummy' # let anyone in regardless of the password

  - or -

     DRIVER => [ 'DBI',
         DBH         => $self->dbh,
         TABLE       => 'user',
         CONSTRAINTS => {
             'user.name'         => '__CREDENTIAL_1__',
             'MD5:user.password' => '__CREDENTIAL_2__'
         },
     ],

  - or -

     DRIVER => [
         [ 'Generic', { user1 => '123' } ],
         [ 'LDAP', binddn => '...', host => 'localhost', ... ]
     ],


=item STORE

Here you can choose how we store the authenticated information after a use has successfully 
logged in.  We need to store the username so that on the next request we can tell the user
has already logged in, and we do not have to present them with another login form.  If you
do not provide the STORE option, then the plugin will look to see if you are using the
L<CGI::Application::Plugin::Session> module nad based on that info use wither the Session
module, or fall back on the Cookie module.  If the module requires extra parameters, you
can pass an array reference that contains as the first parameter the name of the module,
and the rest of the array should contain key value pairs of options for this module.
These storage modules generally live under the CGI::Application::Plugin::Authentication::Store::
namespace, and this part of the package name can be left off when specifying the STORE
parameter.

    STORE => 'Session'

  - or -

    STORE => ['Cookie',
        NAME   => 'MYAuthCookie',
        SECRET => 'FortyTwo',
        EXPIRY => '1d',
    ]


=item POST_LOGIN_RUNMODE

Here you can specify a runmode that the user will be redirected to if they successfully login.

  POST_LOGIN_RUNMODE => 'login'

=item POST_LOGIN_DESTINATION

Here you can specify a URL that the user will be redirected to if they successfully login.
If both POST_LOGIN_DESTINATION and POST_LOGIN_RUNMODE are specified, then the latter
will take precedence.

  POST_LOGIN_DESTINATION => 'http://example.com/start.cgi'


=item LOGIN_RUNMODE

Here you can specify a runmode that the user will be redirected to if they need to login.

  LOGIN_RUNMODE => 'login'

=item LOGIN_DESTINATION

If your login page is external to this module, then you can use this option to specify a
URL that the user will be redirected to when they need to login. If both
LOGIN_DESTINATION and LOGIN_RUNMODE are specified, then the latter will take precedence.

  LOGIN_DESTINATION => 'http://example.com/login.cgi'

=item LOGOUT_RUNMODE

Here you can specify a runmode that the user will be redirected to if they ask to logout.

  LOGOUT_RUNMODE => 'logout'

=item LOGOUT_DESTINATION

If your logout page is external to this module, then you can use this option to specify a
URL that the user will be redirected to when they ask to logout.  If both
LOGOUT_DESTINATION and LOGOUT_RUNMODE are specified, then the latter will take precedence.

  LOGIN_DESTINATION => 'http://example.com/logout.html'


=item CREDENTIALS

Set this to the list of form fields where the user will type in their username and password.
By default this is set to ['authen_username', 'authen_password'].  The form field names should
be set to a value that you are not likely to use in any other forms.  This is important
because this plugin will automatically look for query parameters that match these values on
every request to see if a user is trying to log in.  So if you use the same parameter names
on a user management page, you may inadvertantly perform a login when that was not intended.
Most of the Driver modules will return the first CREDENTIAL as the username, so make sure
that you list the username field first.

  CREDENTIALS => 'authen_password'

  - or -

  CREDENTIALS => [ 'authen_username', 'authen_domain', 'authen_password' ]


=item LOGIN_SESSION_TIMEOUT


This option can be used to tell the system when to force the user to re-authenticate.  There are
a few different possibilities that can all be used concurrently:

=over 4

=item IDLE_FOR

If this value is set, a re-auth will be forced if the user was idle for more then x amount of time.

=item EVERY

If this value is set, a re-auth will be forced every x amount of time.

=item CUSTOM

This value can be set to a subroutine reference that returns true if the session should be timed out,
and false if it is still active.  This can allow you to be very selective about how the timeout system
works.  The authen object will be passed in as the only parameter.

=back

Time values are specified in seconds. You can also specify the time by using a number with the
following suffixes (m h d w), which represent minutes, hours, days and weeks.  The default
is 0 which means the login will never timeout.

Note that the login is also dependant on the type of STORE that is used.  If the Session store is used,
and the session expires, then the login will also automatically expire.  The same goes for the Cookie
store.

For backwards compatibility, if you set LOGIN_SESSION_TIMEOUT to a time value instead of a hashref,
it will be treated as an IDLE_FOR time out.

  # force re-auth if idle for more than 15 minutes
  LOGIN_SESSION_TIMEOUT => '15m'

  # Everyone must re-auth if idle for more than 30 minutes
  # also, everyone must re-auth at least once a day
  # and root must re-auth if idle for more than 5 minutes
  LOGIN_SESSION_TIMEOUT => {
        IDLE_FOR => '30m',
        EVERY    => '1d',
        CUSTOM   => sub {
          my $authen = shift;
          return ($authen->username eq 'root' && (time() - $authen->last_access) > 300) ? 1 : 0;
        }
  }


=back

=cut

sub config {
    my $self  = shift;
    my $class = ref $self ? ref $self : $self;

    die "Calling config after the Authentication object has already been initialized"
        if ref $self && defined $self->{initialized};
    my $config = $self->_config;

    if (@_) {
        my $props;
        if ( ref( $_[0] ) eq 'HASH' ) {
            my $rthash = %{ $_[0] };
            $props = CGI::Application->_cap_hash( $_[0] );
        } else {
            $props = CGI::Application->_cap_hash( {@_} );
        }

        # Check for DRIVER
        if ( defined $props->{DRIVER} ) {
            croak "authen config error:  parameter DRIVER is not a string or arrayref"
              if ref $props->{DRIVER} && Scalar::Util::reftype( $props->{DRIVER} ) ne 'ARRAY';
            $config->{DRIVER} = delete $props->{DRIVER};
            # We will accept a string, or an arrayref of options, but what we really want
            # is an array of arrayrefs of options, so that we can support multiple drivers
            # each with their own custom options
            no warnings qw(uninitialized);
            $config->{DRIVER} = [ $config->{DRIVER} ] if Scalar::Util::reftype( $config->{DRIVER} ) ne 'ARRAY';
            $config->{DRIVER} = [ $config->{DRIVER} ] if Scalar::Util::reftype( $config->{DRIVER}->[0] ) ne 'ARRAY';
        }

        # Check for STORE
        if ( defined $props->{STORE} ) {
            croak "authen config error:  parameter STORE is not a string or arrayref"
              if ref $props->{STORE} && Scalar::Util::reftype( $props->{STORE} ) ne 'ARRAY';
            $config->{STORE} = delete $props->{STORE};
            # We will accept a string, but what we really want is an arrayref of the store driver,
            # and any custom options
            no warnings qw(uninitialized);
            $config->{STORE} = [ $config->{STORE} ] if Scalar::Util::reftype( $config->{STORE} ) ne 'ARRAY';
        }

        # Check for POST_LOGIN_RUNMODE
        if ( defined $props->{POST_LOGIN_RUNMODE} ) {
            croak "authen config error:  parameter POST_LOGIN_RUNMODE is not a string"
              if ref $props->{POST_LOGIN_RUNMODE};
            $config->{POST_LOGIN_RUNMODE} = delete $props->{POST_LOGIN_RUNMODE};
        }

        # Check for POST_LOGIN_DESTINATION
        if ( defined $props->{POST_LOGIN_DESTINATION} ) {
            carp "authen config warning:  parameter POST_LOGIN_DESTINATION ignored since we already have POST_LOGIN_RUNMODE"
              if $config->{POST_LOGIN_RUNMODE};
            croak "authen config error:  parameter POST_LOGIN_DESTINATION is not a string"
              if ref $props->{POST_LOGIN_DESTINATION};
            $config->{POST_LOGIN_DESTINATION} = delete $props->{POST_LOGIN_DESTINATION};
        }

        # Check for LOGIN_RUNMODE
        if ( defined $props->{LOGIN_RUNMODE} ) {
            croak "authen config error:  parameter LOGIN_RUNMODE is not a string"
              if ref $props->{LOGIN_RUNMODE};
            $config->{LOGIN_RUNMODE} = delete $props->{LOGIN_RUNMODE};
        }

        # Check for LOGIN_DESTINATION
        if ( defined $props->{LOGIN_DESTINATION} ) {
            carp "authen config warning:  parameter LOGIN_DESTINATION ignored since we already have LOGIN_RUNMODE"
              if $config->{LOGIN_RUNMODE};
            croak "authen config error:  parameter LOGIN_DESTINATION is not a string"
              if ref $props->{LOGIN_DESTINATION};
            $config->{LOGIN_DESTINATION} = delete $props->{LOGIN_DESTINATION};
        }

        # Check for LOGOUT_RUNMODE
        if ( defined $props->{LOGOUT_RUNMODE} ) {
            croak "authen config error:  parameter LOGOUT_RUNMODE is not a string"
              if ref $props->{LOGOUT_RUNMODE};
            $config->{LOGOUT_RUNMODE} = delete $props->{LOGOUT_RUNMODE};
        }

        # Check for LOGOUT_DESTINATION
        if ( defined $props->{LOGOUT_DESTINATION} ) {
            carp "authen config warning:  parameter LOGOUT_DESTINATION ignored since we already have LOGOUT_RUNMODE"
              if $config->{LOGOUT_RUNMODE};
            croak "authen config error:  parameter LOGOUT_DESTINATION is not a string"
              if ref $props->{LOGOUT_DESTINATION};
            $config->{LOGOUT_DESTINATION} = delete $props->{LOGOUT_DESTINATION};
        }

        # Check for CREDENTIALS
        if ( defined $props->{CREDENTIALS} ) {
            croak "authen config error:  parameter CREDENTIALS is not a string or arrayref"
              if ref $props->{CREDENTIALS} && Scalar::Util::reftype( $props->{CREDENTIALS} ) ne 'ARRAY';
            $config->{CREDENTIALS} = delete $props->{CREDENTIALS};
            # We will accept a string, but what we really want is an arrayref of the credentials
            no warnings qw(uninitialized);
            $config->{CREDENTIALS} = [ $config->{CREDENTIALS} ] if Scalar::Util::reftype( $config->{CREDENTIALS} ) ne 'ARRAY';
        }

        # Check for LOGIN_SESSION_TIMEOUT
        if ( defined $props->{LOGIN_SESSION_TIMEOUT} ) {
            croak "authen config error:  parameter LOGIN_SESSION_TIMEOUT is not a string or a hashref"
              if ref $props->{LOGIN_SESSION_TIMEOUT} && ref$props->{LOGIN_SESSION_TIMEOUT} ne 'HASH';
            my $options = {};
            if (! ref $props->{LOGIN_SESSION_TIMEOUT}) {
                $options->{IDLE_FOR} = _time_to_seconds( $props->{LOGIN_SESSION_TIMEOUT} );
                croak "authen config error: parameter LOGIN_SESSION_TIMEOUT is not a valid time string" unless defined $options->{IDLE_FOR};
            } else {
                if ($props->{LOGIN_SESSION_TIMEOUT}->{IDLE_FOR}) {
                    $options->{IDLE_FOR} = _time_to_seconds( delete $props->{LOGIN_SESSION_TIMEOUT}->{IDLE_FOR} );
                    croak "authen config error: IDLE_FOR option to LOGIN_SESSION_TIMEOUT is not a valid time string" unless defined $options->{IDLE_FOR};
                }
                if ($props->{LOGIN_SESSION_TIMEOUT}->{EVERY}) {
                    $options->{EVERY} = _time_to_seconds( delete $props->{LOGIN_SESSION_TIMEOUT}->{EVERY} );
                    croak "authen config error: EVERY option to LOGIN_SESSION_TIMEOUT is not a valid time string" unless defined $options->{EVERY};
                }
                if ($props->{LOGIN_SESSION_TIMEOUT}->{CUSTOM}) {
                    $options->{CUSTOM} = delete $props->{LOGIN_SESSION_TIMEOUT}->{CUSTOM};
                    croak "authen config error: CUSTOM option to LOGIN_SESSION_TIMEOUT must be a code reference" unless ref $options->{CUSTOM} eq 'CODE';
                }
                croak "authen config error: Invalid option(s) (" . join( ', ', keys %{$props->{LOGIN_SESSION_TIMEOUT}} ) . ") passed to LOGIN_SESSION_TIMEOUT" if %{$props->{LOGIN_SESSION_TIMEOUT}};
            }

            $config->{LOGIN_SESSION_TIMEOUT} = $options;
            delete $props->{LOGIN_SESSION_TIMEOUT};
        }

        # If there are still entries left in $props then they are invalid
        croak "Invalid option(s) (" . join( ', ', keys %$props ) . ") passed to config" if %$props;
    }
}

=head2 protected_runmodes

This method takes a list of runmodes that are to be protected by authentication.  If a user
tries to access one of these runmodes, then they will be redirected to a login page
unless they are properly logged in.  The runmode names can be a list of simple strings, regular
expressions, or special directives that start with a colon.  This method is cumulative, so
if it is called multiple times, the new values are added to existing entries.  It returns
a list of all entries that have been saved so far.

=over 4

=item :all - All runmodes in this module will require authentication

=back

  # match all runmodes
  __PACKAGE__->authen->protected_runmodes(':all');

  # only protect runmodes one two and three
  __PACKAGE__->authen->protected_runmodes(qw(one two three));

  # protect only runmodes that start with auth_
  __PACKAGE__->authen->protected_runmodes(qr/^auth_/);

=cut

sub protected_runmodes {
    my $self   = shift;
    my $config = $self->_config;

    $config->{PROTECTED_RUNMODES} ||= [];
    push @{$config->{PROTECTED_RUNMODES}}, @_ if @_;

    return @{$config->{PROTECTED_RUNMODES}};
}

=head2 is_protected_runmode

This method accepts the name of a runmode, and will tell you if that runmode is
a protected runmode (ie does a user need to be authenticated to access this runmode).

=cut

sub is_protected_runmode {
    my $self = shift;
    my $runmode = shift;

    foreach my $runmode_test ($self->protected_runmodes) {
        if (overload::StrVal($runmode_test) =~ /^Regexp=/) {
            # We were passed a regular expression
            return 1 if $runmode =~ $runmode_test;
        } elsif (ref $runmode_test && ref $runmode_test eq 'CODE') {
            # We were passed a code reference
            return 1 if $runmode_test->($runmode);
        } elsif ($runmode_test eq ':all') {
            # all runmodes are protected
            return 1;
        } else {
            # assume we were passed a string
            return 1 if $runmode eq $runmode_test;
        }
    }

    # See if the user is using attributes
    my $sub = $self->_cgiapp->can($runmode);
    return 1 if $sub && $RUNMODES{$sub};

    return;
}

=head2 redirect_after_login

This method is be called during the prerun stage to
redirect the user to the page that has been configured
as the destination after a successful login.  The location
is based on the values of the POST_LOGIN_RUNMODE or 
POST_LOGIN_DESTINATION config parameter, or in their absense,
the page will be redirected to the page that was originally
requested when the login page was triggered.

=cut

sub redirect_after_login {
    my $self = shift;
    my $cgiapp = $self->_cgiapp;
    my $config = $self->_config;

    if ($config->{POST_LOGIN_RUNMODE}) {
        $cgiapp->prerun_mode($config->{POST_LOGIN_RUNMODE});
    } elsif ($config->{POST_LOGIN_DESTINATION}) {
        $cgiapp->header_add(-location => $config->{POST_LOGIN_DESTINATION});
        $cgiapp->prerun_mode('authen_dummy_redirect');
    } elsif (my $destination = $cgiapp->query->param('destination')) {
        $cgiapp->header_add(-location => $destination);
        $cgiapp->prerun_mode('authen_dummy_redirect');
#--------------------------------------------------
#     } else {
#         $cgiapp->header_add(-location => $cgiapp->query->url(absolute => 1));
#         $cgiapp->prerun_mode('authen_dummy_redirect');
#-------------------------------------------------- 
    }
}

=head2 redirect_to_login

This method is be called during the prerun stage if
the current user is not logged in, and they are trying to
access a protected runmode.  It will redirect to the page
that has been configured as the login page, based on the value
of LOGIN_RUNMODE or LOGIN_DESTINATION.  If nothing is configured
a simple login page will be automatically provided.

=cut

sub redirect_to_login {
    my $self = shift;
    my $cgiapp = $self->_cgiapp;
    my $config = $self->_config;

    if ($config->{LOGIN_RUNMODE}) {
        $cgiapp->prerun_mode($config->{LOGIN_RUNMODE});
    } elsif ($config->{LOGIN_DESTINATION}) {
        $cgiapp->header_add(-location => $config->{LOGIN_DESTINATION});
        $cgiapp->prerun_mode('authen_dummy_redirect');
    } else {
        $cgiapp->prerun_mode('authen_login');
    }
}

=head2 redirect_to_logout

This method is called during the prerun stage if the user
has requested to be logged out.  It will redirect to the page
that has been configured as the logout page, based on the value
of LOGOUT_RUNMODE or LOGOUT_DESTINATION.  If nothing is
configured, the page will redirect to the website homepage.

=cut

sub redirect_to_logout {
    my $self = shift;
    my $cgiapp = $self->_cgiapp;
    my $config = $self->_config;
    $self->logout();

    if ($config->{LOGOUT_RUNMODE}) {
        $cgiapp->prerun_mode($config->{LOGOUT_RUNMODE});
    } elsif ($config->{LOGOUT_DESTINATION}) {
        $cgiapp->header_add(-location => $config->{LOGOUT_DESTINATION});
        $cgiapp->prerun_mode('authen_dummy_redirect');
    } else {
        $cgiapp->header_add(-location => '/');
        $cgiapp->prerun_mode('authen_dummy_redirect');
    }
}

=head2 setup_runmodes

This method is called during the prerun stage to register some custom
runmodes that the Authentication plugin requires in order to function.

=cut

sub setup_runmodes {
    my $self   = shift;
    my $config = $self->_config;

    $self->_cgiapp->run_modes( authen_login => \&authen_login_runmode )
      unless $config->{LOGIN_RUNMODE} || $config->{LOGIN_DESTINATION};
    $self->_cgiapp->run_modes( authen_logout => \&authen_logout_runmode )
      unless $config->{LOGOUT_RUNMODE} || $config->{LOGOUT_DESTINATION};
    $self->_cgiapp->run_modes( authen_dummy_redirect => \&authen_dummy_redirect );
    return;
}

=head2 last_login

This will return return the time of the last login for this user

  my $last_login = $self->authen->last_login;

=cut

sub last_login {
    my $self = shift;
    my $new  = shift;
    $self->initialize;

    return unless $self->username;
    my $old = $self->store->fetch('last_login');
    $self->store->save('last_login' => $new) if $new;
    return $old;
}

=head2 last_access

This will return return the time of the last access for this user

  my $last_access = $self->authen->last_access;

=cut

sub last_access {
    my $self = shift;
    my $new  = shift;
    $self->initialize;

    return unless $self->username;
    my $old = $self->store->fetch('last_access');
    $self->store->save('last_access' => $new) if $new;
    return $old;
}

=head2 is_login_timeout

This will return true or false depending on whether the users login status just timed out

  $self->add_message('login session timed out') if $self->authen->is_login_timeout;

=cut

sub is_login_timeout {
    my $self = shift;
    $self->initialize;

    return $self->{is_login_timeout} ? 1 : 0;
}

=head2 is_authenticated

This will return true or false depending on the login status of this user

  assert($self->authen->is_authenticated); # The user should be logged in if we got here

=cut

sub is_authenticated {
    my $self = shift;
    $self->initialize;

    return $self->username ? 1 : 0;
}

=head2 login_attempts

This method will return the number of failed login attempts have been made by this
user since the last successfull login.  This is not a number that can be trusted,
as it is dependant on the underlying store to be able to return the correct value for
this user.  For example, if the store uses a cookie based session, the user trying
to login could delete their cookies, and hence get a new session which will not have
any login attempts listed.  The number will be cleared upon a successful login.

=cut

sub login_attempts {
    my $self = shift;
    $self->initialize;

    my $la = $self->store->fetch('login_attempts');
    return $la;
}

=head2 username

This will return the username of the currently logged in user, or undef if
no user is currently logged in.

  my $username = $self->authen->username;

=cut

sub username {
    my $self = shift;
    $self->initialize;

    my $u = $self->store->fetch('username');
    return $u;
}

=head2 is_new_login

This will return true or false depending on if this is a fresh login

  $self->log->info("New Login") if $self->authen->is_new_login;

=cut

sub is_new_login {
    my $self = shift;
    $self->initialize;

    return $self->{is_new_login};
}

=head2 credentials

This method will return the names of the form parameters that will be
looked for during a login.  By default they are authen_username and authen_password,
but these values can be changed by supplying the CREDENTIALS parameters in the
configuration.

=cut

sub credentials {
    my $self = shift;
    my $config = $self->_config;
    return $config->{CREDENTIALS} || [qw(authen_username authen_password)];
}

=head2 logout

This will attempt to logout the user.  If during a request the Authentication
module sees a parameter called 'authen_logout', it will automatically call this method
to log out the user.

  $self->authen->logout();

=cut

sub logout {
    my $self = shift;
    $self->initialize;

    $self->store->clear;
}

=head2 drivers

This method will return a list of driver objects that are used for
verifying the login credentials.

=cut

sub drivers {
    my $self = shift;

    if ( !$self->{drivers} ) {
        my $config = $self->_config;

        # Fetch the configuration parameters for the driver(s)
        my $driver_configs = defined $config->{DRIVER} ? $config->{DRIVER} : [['Dummy']];

        foreach my $driver_config (@$driver_configs) {
            my ($drivername, @params) = @$driver_config;
            # Load the the class for this driver
            my $driver_class = _find_deligate_class(
                'CGI::Application::Plugin::Authentication::Driver::' . $drivername,
                $drivername
            ) || die "Driver ".$drivername." can not be found";

            # Create the driver object
            my $driver = $driver_class->new( $self, @params )
              || die "Could not create new $driver_class object";
            push @{$self->{drivers}}, $driver;
        }
    }

    my $drivers = $self->{drivers};
    return @$drivers[0..$#$drivers];
}

=head2 store

This method will return a store object that is used to store information
about the status of the authentication across multiple requests.

=cut

sub store {
    my $self = shift;

    if ( !$self->{store} ) {
        my $config = $self->_config;

        # Fetch the configuration parameters for the store
        my ($store_module, @store_config) = @{ $config->{STORE} } if $config->{STORE} && ref $config->{STORE} eq 'ARRAY';
        if (!$store_module) {
            # No STORE configuration was provided
            if ($self->_cgiapp->can('session') && UNIVERSAL::isa($self->_cgiapp->session, 'CGI::Session')) {
                # The user is already using the Session plugin
                ($store_module, @store_config) = ( 'Session' );
            } else {
                # Fall back to the Cookie Store
                ($store_module, @store_config) = ( 'Cookie' );
            }
        }

        # Load the the class for this store
        my $store_class = _find_deligate_class(
            'CGI::Application::Plugin::Authentication::Store::' . $store_module,
            $store_module
        ) || die "Store $store_module can not be found";

        # Create the store object
        $self->{store} = $store_class->new( $self, @store_config )
          || die "Could not create new $store_class object";
    }

    return $self->{store};
}

=head2 initialize

This does most of the heavy lifting for the Authentication plugin.  It will
check to see if the user is currently attempting to login by looking for
the credential form fields in the query object.  It will load the required
driver objects and authenticate the user.  It is OK to call this method multiple
times as it checks to see if it has already been executed and will just return
without doing anything if called multiple times.  This allows us to call
initialize as late as possible in the request so that no unnecesary work is done.

=cut

sub initialize {
    my $self = shift;
    return if $self->{initialized};

    $self->{initialized} = 1;

    my $config = $self->_config;

    # See if the user is trying to log in
    #  We do this before checking to see if the user is already logged in, since
    #  a logged in user may want to log in as a different user.
    my $field_names = $config->{CREDENTIALS} || [qw(authen_username authen_password)];

    my $query = $self->_cgiapp->query;
    my @credentials = map { $query->param($_) } @$field_names;
    if ($credentials[0]) {
        # The user is trying to login
        # make sure if they are already logged in, that we log them out first
        my $store = $self->store;
        $store->clear if $store->fetch('username');
        foreach my $driver ($self->drivers) {
            if (my $username = $driver->verify_credentials(@credentials)) {
                # This user provided the correct credentials
                # so save this new login in the store
                my $now = time();
                $store->save( username => $username,  login_attempts => 0, last_login => $now, last_access => $now );
                $self->{is_new_login} = 1;
                last;
            }
        }
        unless ($self->username) {
            # password mismatch - increment failed login attempts
            my $attempts = $store->fetch('login_attempts') || 0; 
            $store->save( login_attempts => $attempts + 1 );
        }
    }

    if ($self->username && $config->{LOGIN_SESSION_TIMEOUT} && !$self->{is_new_login}) {
        # This is not a fresh login, and there are time out rules, so make sure the login is still valid
        if ($config->{LOGIN_SESSION_TIMEOUT}->{IDLE_FOR} && time() - $self->last_access >= $config->{LOGIN_SESSION_TIMEOUT}->{IDLE_FOR}) {
            # this login has been idle for too long
            $self->{is_login_timeout} = 1;
            $self->logout;
        } elsif ($config->{LOGIN_SESSION_TIMEOUT}->{EVERY} && time() - $self->last_login >=  $config->{LOGIN_SESSION_TIMEOUT}->{EVERY}) {
            # it has been too long since the last login
            $self->{is_login_timeout} = 1;
            $self->logout;
        } elsif ($config->{LOGIN_SESSION_TIMEOUT}->{CUSTOM} && $config->{LOGIN_SESSION_TIMEOUT}->{CUSTOM}->($self)) {
            # this login has timed out
            $self->{is_login_timeout} = 1;
            $self->logout;
        }

    }

}

=head2 login_box

This method will return the HTML for a login box that can be
embedded into another page.  This is the same login box that is used
in the default authen_login runmode that the plugin provides.

TODO: Allow the user to provide custom styles for rendering this page

=cut

sub login_box {
    my $self        = shift;
    my $query       = $self->_cgiapp->query;
    my $credentials = $self->credentials;
    my $runmode     = $self->_cgiapp->get_current_runmode;
    my $destination = $query->param('destination') || $query->self_url;
    my $action      = $query->url( -absolute => 1 );
    my $username    = $credentials->[0];
    my $password    = $credentials->[1];
    my $messages    = '';
    if ( my $attempts = $self->login_attempts ) {
        $messages .= qq{<li class="warning">Invalid username or password<br />(login attempt $attempts)</li>};
    } else {
        $messages .= "<li>Please enter your username and password in the fields below.</li>";
    }
    return <<END;
<div class="login">
  <div class="title">
    <h4>Login</h4>
  </div>

  <div class="content">
    <form name="loginform" method="post" action="${action}">
      <ul class="message">${messages}</ul>
      <fieldset>
        <label for="${username}">Username</label><input id="authen_loginfield" tabindex="1" type="text" name="${username}" size="30" value="" />
        <label for="${password}">Password</label><input id="authen_passwordfield" tabindex="2" type="password" name="${password}" size="30" />
        <div class="buttons">
          <input type="hidden" name="destination" value="${destination}" />
          <input type="hidden" name="rm" value="${runmode}" />
          <input tabindex="3" type="submit" name="login" value="Log in" class="button" />
          <input tabindex="4" type="reset" name="resetlogin" value="Reset" class="button" />
        </div>
      </fieldset>
    </form>
  </div>
</div>
END
}

=head2 login_styles

This method returns a stylesheet that can be used for the login box that
the plugin provides.  Currently the login box automatically includes these
default styles in the page.

=cut

sub login_styles {
    return <<END;
body {
    font-family: arial, helvetica, sans-serif;
    background-color: #ddd;
}

div, fieldset {
    margin: 0;
    padding: 0;
    border: none;
}

div.login {
    position: absolute;
    top: 0;
    right: 0;
    bottom: 0;
    left: 0;
    width: 25em;
    height: 50%;
    margin: auto;
    padding: 2em;
    font-size: 80%;
    font-weight: bold;
}

div.login .title {
    background: green;
    -moz-border-radius: 12px 12px 0 0;
    border-radius: 12px 12px 0 0;
    border-top: 1px solid black;
    border-left: 1px solid black;
    border-right: 1px solid black;
    text-align: center;
}

div.login .content {
    background: white;
    padding: 0.8em;
    -moz-border-radius: 0 0 12px 12px;
    border-radius: 0 0 12px 12px;
    border-bottom: 1px solid black;
    border-left: 1px solid black;
    border-right: 1px solid black;
}

div.login h4 {
    margin: 0;
    padding: .3em .6em;
    color: #fff;
    font-size: 150%;
}

div.login label {
    display: block;
    padding: 1em 0 0 0;
}

div.login div.buttons {
    display: block;
    margin: 8px 4px;
    width: 100%;
    text-align: center;
}

#authen_loginfield:focus {
    background-color: #ffc;
    color: #000;
}

#authen_passwordfield:focus {
    background-color: #ffc;
    color: #000;
}

/* image courtesy of http://www.famfamfam.com/lab/icons/silk/  */
#authen_loginfield {
    background: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAG5SURBVHjaYvz//z8DJQAggFiIVfh0twHn9w8KD9+/ZBT+9/cfExfvwwc87GxWAAFEtAFf3yl++/9XikHXL56BkYmJ4dKmcoUPT99PBQggRmK8ALT9v4BUBQMLrxxQMztY7N+PjwyXtk76BxBATMRoFjGewsDCx8jw9Oxyht9vboIxCDAxs/wCCCC8LoBrZv/A8PPpVoZ/39gZ7p57xcDLJ8Xw5tkdBrO8DYwAAcRElOYXaxn+/73DwC4vzyAmzsLw58kJsGaQOoAAYiJK868nDGwSXgxvjp1n+Hz7HoNawRFGmFqAAMIw4MBEDaI1gwBAAKEYsKtL/b9x2HSiNYMAQACBA3FmiqKCohrbfQ2nLobn97Yz6Br/JEozCAAEEDgh/eb6d98yYhEDBxsnw5VNZxnOffjLIKltw/D52B6GH89fMVjUnGbEFdgAAQRPiexMzAyfDk9gMJbmYbh17irDueMrGbjExBi8Oy8z4ksnAAEENuDY1S8MjjsnMSgaezJ8Z2Bm+P95PgPX6ycENYMAQACBwyDSUeQ/GzB926kLMEjwsjOwifKvcy05EkxMHgEIIEZKszNAgAEA+j3MEVmacXUAAAAASUVORK5CYII=') no-repeat 0 1px;
    padding-left: 18px;
}

/* image courtesy of http://www.famfamfam.com/lab/icons/silk/  */
#authen_passwordfield {
    background: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAKbSURBVHjaYvz//z8DPvBko+s0IJUJ5U6X8d+dhSwPEEAMIANw4ccbXKYB8f8/P+6BMYgNEkNWAxBAhDV/Pff/5+t5/39/2gcU/gc25P5qpzkwdQABxIjNCzBnS7p2Mfz5tJ+BkVWE4dWRxWA5oBcYHiyyYnj5heGAedYxR4AAwmXAf0mPWQx/3q9n+P/3I9AAMaCoBsPr4x0MDH/+MUgHrGG4P8eF4fVf9gMAAcSEK/D+/3oA1gxm/3kLJG8wSDhWMAjoeTJ8fxjNoJDQzyD0+7sDQACx4DKAkVWcgZGZG2jIV6AJfxn+/37F8OfPO6BhRxl+f/nIwC7xluHPm58MAAHEhMX5ILHp787OYvj/7zvDr7f7Gf59vw804DUwPM4x/P3+loFb0ZfhVlc1wxMu7psAAcSCEd9MjAzswoYMAppmDD9e9DKwcIkwMHFyMPx+dZnh7+9vDDxqwQx3Ji1jeMrJc9W1/JQOQAAheyFT2mctw9+vpxh+fz7A8O1JDQMrEz/QK2YMb47uZpD0SmEAmsRwu7eJ4QUX1wWXklOGIE0AAcQIim9YShOzSmf49W4xw5+PdxlYeIUYWLh9GS6vXPH+3U/Gd3K/vikzcTAzvOTkOmNXeNIUZitAALFAbF4D9N8Bhl+vJjP8/vCUgY1fkoGZ24PhysoV7178Y9vmW3M8FqZBHS3MAAIIZMDnP59P835/3Mnw98t7Bg5xNQZGNnOgzSvfv2ZgX+dbfiwVX14BCCCQAbyMrNwMDKxcDOxi/Az/WU0YLi1b8/E9K8cqr6JjGQwEAEAAMf378+/cn+//GFi5bRiYuMOBzt7w4RMH50IPIjSDAEAAsbz8+Gfdh9VFEr9//WX7//s/009uzlmuWUcqGYgEAAEGAIZWUhP4bjW1AAAAAElFTkSuQmCC') no-repeat 0 1px;
    padding-left: 18px;
}

ul.message {
    margin-top: 0;
    margin-bottom: 0;
    list-style: none;
}

ul.message li {
    text-indent: -2em;
    padding: 0px;
    margin: 0px;
}

ul.message li.warning {
    color: red;
}

END
}

=head2 new

This method creates a new CGI::Application::Plugin::Authentication object.  It requires
as it's only parameter a CGI::Application object.  This method should never be called
directly, since the 'authen' method that is imported into the CGI::Application module
will take care of creating the CGI::Application::Plugin::Authentication object when it
is required.

=cut

sub new {
    my $class  = shift;
    my $cgiapp = shift;
    my $self   = {};

    bless $self, $class;
    $self->{cgiapp} = $cgiapp;
    Scalar::Util::weaken($self->{cgiapp}); # weaken circular reference

    return $self;
}

=head2 instance

This method works the same way as 'new', except that it returns the same Authentication
object for the duration of the request.  This method should never be called
directly, since the 'authen' method that is imported into the CGI::Application module
will take care of creating the CGI::Application::Plugin::Authentication object when it
is required.

=cut

sub instance {
    my $class  = shift;
    my $cgiapp = shift;
    die "CGI::Application::Plugin::Authentication->instance must be called with a CGI::Application object"
      unless defined $cgiapp && UNIVERSAL::isa( $cgiapp, 'CGI::Application' );

    $cgiapp->{__CAP_AUTHENTICATION_INSTANCE} = $class->new($cgiapp) unless defined $cgiapp->{__CAP_AUTHENTICATION_INSTANCE};
    return $cgiapp->{__CAP_AUTHENTICATION_INSTANCE};
}


=head1 CGI::Application CALLBACKS

=head2 prerun_callback

This method is a CGI::Application prerun callback that will be
automatically registered for you if you are using CGI::Application
4.0 or greater.  If you are using an older version of CGI::Application
you will have to create your own cgiapp_prerun method and make sure you
call this method from there.

 sub cgiapp_prerun {
    my $self = shift;

    $self->CGI::Application::Plugin::Authentication::prerun_callback();
 }

=cut

sub prerun_callback {
    my $self = shift;
    my $authen = $self->authen;

    $authen->initialize;

    # setup the default login and logout runmodes
    $authen->setup_runmodes;

    # The user is asking to be logged out
    if ($self->query->param('authen_logout')) {
        # The user wants to logout
        return $self->authen->redirect_to_logout;
    }

    # If the user just logged in then we may want to redirect them
    if ($authen->is_new_login) {
        # User just logged in, so where to we send them?
        return $self->authen->redirect_after_login;
    }

    # Update any time out info
    my $config = $authen->_config;
    if ( $config->{LOGIN_SESSION_TIMEOUT} ) {
        # update the last access time
        my $now = time;
        $authen->last_access($now);
    }

    if ($authen->is_protected_runmode($self->get_current_runmode)) {
        # This runmode requires authentication
        unless ($authen->is_authenticated) {
            # This user is NOT logged in
            return $self->authen->redirect_to_login;
        }
    }
}

=head1 CGI::Application RUNMODES

=head2 authen_login_runmode

This runmode is provided if you do not want to create your
own login runmode.  It will display a simple login form for the user.

=cut

sub authen_login_runmode {
    my $self = shift;
    my $q    = $self->query;

    my $credentials = $self->authen->credentials;
    my $username    = $credentials->[0];
    my $password    = $credentials->[1];
    my $html        = join( "\n",
        CGI::start_html(
            -title  => 'Login',
            -style  => { -code => $self->authen->login_styles },
            -onload => "document.loginform.${username}.focus()",
        ),
        $self->authen->login_box,
        CGI::end_html(),
    );

    return $html;
}

=head2 authen_dummy_redirect

This runmode is provided for convenience when an external redirect needs
to be done.  It just returns an empty string.

=cut

sub authen_dummy_redirect {
    return '';
}

###
### Helper methods
###

sub _cgiapp {
    return $_[0]->{cgiapp};
}

sub _find_deligate_class {
    foreach my $class (@_) {
        $class->require && return $class;
    }
    return;
}

sub _config {
    my $self  = shift;
    my $class = ref $self ? ref $self : $self;
    my $config;
    if ( ref $self ) {
        $config = $self->{__CAP_AUTHENTICATION_CONFIG} ||= $__CONFIG{$class} || {};
    } else {
        $__CONFIG{$class} ||= {};
        $config = $__CONFIG{$class};
    }
    return $config;
}

###
### Helper functions
###

sub _time_to_seconds {
    my $time = shift;
    return unless defined $time;

    # Most of this function is borrowed from CGI::Util v1.4 by Lincoln Stein
    my (%mult) = (
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 60 * 60 * 24,
        'w' => 60 * 60 * 24 * 7,
        'M' => 60 * 60 * 24 * 30,
        'y' => 60 * 60 * 24 * 365
    );
    # format for time can be in any of the forms...
    # "180" -- in 180 seconds
    # "180s" -- in 180 seconds
    # "2m" -- in 2 minutes
    # "12h" -- in 12 hours
    # "1d"  -- in 1 day
    # "4w"  -- in 4 weeks
    # "3M"  -- in 3 months
    # "2y"  -- in 2 years
    my $offset;
    if ( $time =~ /^([+-]?(?:\d+|\d*\.\d*))([smhdwMy]?)$/ ) {
        return if (!$2 || $2 eq 's') && $1 != int $1; # 
        $offset = int ( ( $mult{$2} || 1 ) * $1 );
    }
    return $offset;
}


=head1 EXAMPLE

In a CGI::Application module:

  use CGI::Application::Plugin::AutoRunmode;
  use CGI::Application::Plugin::Session;
  use CGI::Application::Plugin::Authentication;
  use base qw(CGI::Application);
  
  __PACKAGE__->authen->config(
        DRIVER         => [ 'Generic', { user1 => '123' } ],
        STORE          => 'Session',
        LOGOUT_RUNMODE => 'start',
  );
  __PACKAGE__->authen->protected_runmodes(qr/^auth_/, 'one');

  sub start : RunMode {
    my $self = shift;

  }

  sub one : RunMode {
    my $self = shift;
 
    # The user will only get here if they are logged in
  }

  sub auth_two : RunMode {
    my $self = shift;
 
    # This is also protected because of the
    # regexp call to protected_runmodes above
  }


=head1 TODO

There are lots of things that can still be done to improve this plugin.  If anyone else is interested
in helping out feel free to dig right in.  Many of these things don't need my input, but if you want
to avoid duplicated efforts, send me a note, and I'll let you know of anyone else is working in the same area.

=over 4

=item write a tutorial

=item build more Drivers (Class::DBI, LDAP, Radius, etc...)

=item Add support for method attributes to identify runmodes that require authentication

=item finish the test suite

=item provide more example code

=item clean up the documentation

=item build a DB driver that builds it's own table structure.  This can be used by people that don't have their oen user database to work with, and could include a simple user management application.


=back

=head1 BUGS

This is alpha software and as such, the features and interface
are subject to change.  So please check the Changes file when upgrading.


=head1 SEE ALSO

L<CGI::Application>, perl(1)


=head1 AUTHOR

Cees Hek <ceeshek@gmail.com>

=head1 CREDITS

Thanks to SiteSuite (http://www.sitesuite.com.au) for funding the 
development of this plugin and for releasing it to the world.


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2005, SiteSuite. All rights reserved.

This module is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

=cut

1;

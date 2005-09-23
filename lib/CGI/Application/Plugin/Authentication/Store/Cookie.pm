package CGI::Application::Plugin::Authentication::Store::Cookie;

use strict;
use warnings;

use base qw(CGI::Application::Plugin::Authentication::Store);
use UNIVERSAL::require;

=head1 NAME

CGI::Application::Plugin::Authentication::Store::Cookie - Cookie based Store


=head1 SYNOPSIS

 use base qw(CGI::Application);
 use CGI::Application::Plugin::Session;
 use CGI::Application::Plugin::Authentication;

  __PACKAGE__->authen->config(
        STORE => ['Cookie', SECRET => "Shhh, don't tell anyone", NAME => 'CAPAUTH_DATA', EXPIRY => '+1y'],
  );

=head1 DESCRIPTION

This module uses a cookie to store authentication information across multiple requests.
It works by creating a cookie that contains the information we would like to store, then base64
the data.  In order to ensure the the information was not manipulated by the user, we include
a CRC checksum that is generated along with our secret.  Since the user does not know the value
of the secret, the will not be able to recreate the checksum after change some values, so we
will be able to tell if the information has been manipulated.

=head1 DEPENDENCIES

This module requires the following modules to be available.

=over 4

=item MIME::Base64

=item Digest::SHA1

=item CGI::Cookie

=back

=head1 METHODS

=head2 fetch

This method accepts a list of parameters and fetches them from the cookie data.

=cut

sub fetch {
    my $self = shift;
    my @items = map { $self->{cookie}->{data}->{$_} } @_;
    return @items[0..$#items];
}

=head2 save

This method accepts a hash of parameters and values and stores them in the cookie data.

=cut

sub save {
    my $self = shift;
    my %items = @_;
    while (my ($param, $value) = each %items) {
        $self->{cookie}->{data}->{$param} = $value;
    }
    $self->_register_postrun_callback;
    return 1;
}

=head2 delete

This method accepts a list of parameters and deletes them from the cookie data.

=cut

sub delete {
    my $self = shift;
    foreach my $param (@_) {
        delete $self->{cookie}->{data}->{$param};
    }
    $self->_register_postrun_callback;
    return 1;
}

=head2 initialize

This method will check for an existing cookie, and decode the contents for later retrieval.

=cut

sub initialize {
    my $self = shift;

    # Check for CGI::Cookie
    die "CGI::Cookie is required to use the Cookie store" unless CGI::Cookie->require;

    # Check for MIME::Base64
    die "MIME::Base64 is required to use the Cookie store" unless MIME::Base64->require;

    # Check for Digest::SHA1
    die "Digest::SHA1 is required to use the Cookie store" unless Digest::SHA1->require;

    my @options = $self->options;
    die "Invalid Store Configuration for the Cookie store - options section must contain a hash of values" if @options % 2;
    my %options = @options;
    $self->{cookie}->{options} = \%options;

    my %cookies = CGI::Cookie->fetch;
    if ($cookies{$self->cookie_name}) {
        my $rawdata = $cookies{$self->cookie_name}->value;
        $self->{cookie}->{data} = $self->_decode($rawdata);
    }
    $self->_register_postrun_callback;

    return;
}

=head2 cookie_name

This method will return the name of the cookie

=cut

sub cookie_name {
    my $self = shift;
    return $self->{cookie}->{options}->{NAME} || 'CAPAUTH_DATA';
}

###
### Helper methods
###

# _register_postrun_callback
#
# We only register the postrun callback once a change has been made to the data
# so that we don't unecesarily send out a cookie.
sub _register_postrun_callback {
    my $self = shift;
    return if $self->{cookie}->{postrun_registered}++;

    $self->authen->_cgiapp->add_callback('postrun', \&_postrun_callback);
    return;
}

# _postrun_callback
#
# This callback will add a cookie to the outgoing headers at the postrun stage
sub _postrun_callback {
    my $self = shift;

    my $store = $self->authen->store;
    my $rawdata = $store->_encode($store->{cookie}->{data});

    my $cookie = new CGI::Cookie(-name => $store->cookie_name,-value => $rawdata);
    $self->header_add(-cookie => [$cookie]);
    return;
}

# _decode
#
# Take a raw cookie value, and decode and verify the data
sub _decode {
    my $self = shift;
    my $rawdata = MIME::Base64::decode(shift) || return;

    my %hash = map { split /\=/, $_, 2 } split /\0/, $rawdata;

    my $checksum = delete $hash{c};
    # verify checksum
    if ($checksum eq Digest::SHA1::sha1_base64(join("\0", $self->{cookie}->{options}->{SECRET}, sort values %hash))) {
        # Checksum verifies so the data is clean
        return \%hash;
    } else {
        # The data could not be verified, so we trash it all
        return;
    }
}

# _encode
#
# Take the data we want to store and encode the data into a cookie
sub _encode {
    my $self = shift;
    my $hash = shift;
    my %hash = %$hash;

    my $checksum = Digest::SHA1::sha1_base64(join("\0", $self->{cookie}->{options}->{SECRET}, sort values %hash));
    $hash{c} = $checksum;
    my $rawdata = join("\0", map { join('=', $_, $hash{$_}) } keys %hash);
    return MIME::Base64::encode($rawdata, "");
}


=head1 SEE ALSO

L<CGI::Application::Plugin::Authentication::Store>, L<CGI::Application::Plugin::Authentication>, perl(1)


=head1 AUTHOR

Cees Hek <ceeshek@gmail.com>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2005, SiteSuite. All rights reserved.

This module is free software; you can redistribute it and/or modify it under the same terms as Perl itself.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

=cut

1;

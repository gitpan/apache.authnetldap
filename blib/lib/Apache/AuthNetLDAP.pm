package Apache::AuthNetLDAP;


#allow people to authenticate with LDAP server via Net::LDAP module
#used Apache::AuthPerLDAP as basis

# (c) 1999 University of North Texas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the University nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTERS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

use Net::LDAP;
use mod_perl;
use Apache::Constants qw(OK AUTH_REQUIRED);


require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
$VERSION = '0.01';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Apache::AuthNetLDAP macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap Apache::AuthNetLDAP $VERSION;

# Preloaded methods go here.

#handles Apache requests
sub handler
{
   my $r = shift; 

   my ($result, $password) = $r->get_basic_auth_pw;
   return $result if $result; 
  
   my $username = $r->connection->user;

   my $binddn = $r->dir_config('BindDN') || "";
   my $bindpwd = $r->dir_config('BindPWD') || "";
   my $basedn = $r->dir_config('BaseDN') || "";
   my $ldapserver = $r->dir_config('LDAPServer') || "localhost";
   my $ldapport = $r->dir_config('LDAPPort') || 389;
   my $uidattr = $r->dir_config('UIDAttr') || "uid";
 
    if ($password eq "") {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: no password supplied",$r->uri);
        return AUTH_REQUIRED;
    }
 
  
   my $ldap = new Net::LDAP($ldapserver, port => $ldapport);

   #initial bind as user in Apache config
   my $mesg = $ldap->bind($binddn, password=>$bindpwd);
  
   #each error message has an LDAP error code
   if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED; 
   }
  
  
  #Look for user based on UIDAttr
  
   my $attrs = ['dn'];
  $mesg = $ldap->search(
                  base => $basedn,
                  scope => 'sub',                  
                  filter => "($uidattr=$username)",
                  attrs => $attrs
                 );

    if (my $error = $mesg->code())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: LDAP Connection Failed: $error",$r->uri);
        return AUTH_REQUIRED;
   }

   unless ($mesg->count())
   {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: user entry not found for filter: $uidattr=$username",$r->uri);
        return AUTH_REQUIRED;
   }
 
   #now try to authenticate as user
   my $entry = $mesg->shift_entry;
   $mesg = $ldap->bind($entry->dn(),password=>$password);

 
  if (my $error = $mesg->code())
  {
        $r->note_basic_auth_failure;
        $r->log_reason("user $username: failed bind: $error",$r->uri);
        return AUTH_REQUIRED;
   }
        my $error = $mesg->code();
        my $dn = $entry->dn();
        #$r->log_reason("AUTHDEBUG user $dn:$password bind: $error",$r->uri);

 return OK;
}
# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Apache::AuthNetLDAP - mod_perl module that uses the Net::LDAP module for user authentication for Apache 

=head1 SYNOPSIS

 AuthName "LDAP Test Auth"
 AuthType Basic

 #only set the next two if you need to bind as a user for searching
 #PerlSetVar BindDN "uid=user1,ou=people,o=acme.com" #optional
 #PerlSetVar BindPWD "password" #optional
 PerlSetVar BaseDN "ou=people,o=acme.com"
 PerlSetVar LDAPServer ldap.acme.com
 PerlSetVar LDAPPort 389
 #PerlSetVar UIDAttr uid
 PerlSetVar UIDAttr mail

 require valid-user

 PerlAuthenHandler Apache::AuthNetLDAP

=head1 DESCRIPTION

This module authenticates users via LDAP using the Net::LDAP module. This module is Graham Barr's "pure" Perl LDAP API. 

It also uses all of the same parameters as the Apache::AuthPerLDAP, but I have added two extra parameters. 

The parameters are:

=over 4

=item PerlSetVar BindDN

Used to set initial LDAP user.

=item PerlSetVar BindPWD

Used to set initial LDAP password.

=item PerlSetVar BaseDN

This sets the search base used when looking up a user in an LDAP server.

=item PerlSetVar LDAPServer 

This is the hostname of the LDAP server you wish to use.

=item PerlSetVar LDAPPort 

This is the port the LDAP server is listening on.

=item PerlSetVar UIDAttr

The attribute used to lookup the user.

=back

=head2 Uses for UIDAttr

For example if you set the UIDAttr to uid, then the LDAP search filter will lookup a user using the search filter:

Normally you will use the uid attribute, but you may want (need) to use a different attribute depending on your LDAP server or to synchronize with different applications. For example some versions of Novell's LDAP servers that I've encountered stored the user's login name in the cn attribute (a really bad idea). And the Netscape Address Book uses a user's email address as the login id.

=head1 INSTALLATION 

It's a pretty straightforward install if you already have mod_perl and Net::LDAP already installed.

After you have unpacked the distribution type:

perl Makefile.PL
make 
make install

Then in your httpd.conf file or .htaccess file, in either a <Directory> or <Location> section put:

 AuthName "LDAP Test Auth"
 AuthType Basic

 #only set the next two if you need to bind as a user for searching
 #PerlSetVar BindDN "uid=user1,ou=people,o=acme.com" #optional
 #PerlSetVar BindPWD "password" #optional
 PerlSetVar BaseDN "ou=people,o=acme.com"
 PerlSetVar LDAPServer ldap.acme.com
 PerlSetVar LDAPPort 389
 PerlSetVar UIDAttr uid 

 require valid-user

 PerlAuthenHandler Apache::AuthNetLDAP

=head1 HOMEPAGE

	Module Home:http://courses.unt.edu/mewilcox/

=head1 AUTHOR
  	(c) 1999 University of North Texas
   	Mark Wilcox mewilcox@unt.edu

=head1 SEE ALSO
   L<Net::LDAP>
  

=head1 ACKNOWLEDGMENTS

 Graham Barr for writing Net::LDAP module.
 Henrik Strom for writing the Apache::AuthPerLDAP module which I derived this from.
 The O'Reilly "Programming Modules for Apache with Perl and C" (http://www.modperl.com).

=cut

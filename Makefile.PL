use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
eval
{
require Net::LDAP;
}; 
if ($@) { die("You need the Net::LDAP module to use this module");}

#require URI::ldap;

WriteMakefile(
    'NAME'	=> 'Apache::AuthNetLDAP',
    'VERSION_FROM' => 'AuthNetLDAP.pm', # finds $VERSION
);

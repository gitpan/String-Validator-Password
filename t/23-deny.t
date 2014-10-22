#!perl -T

use Test::More tests => 27;

BEGIN {
    use_ok( 'String::Validator::Password' ) || print "Bail out!\n";
}

diag( "Testing String::Validator::Password $String::Validator::Password::VERSION, Perl $], $^X" );

# Test with just default values.

my $lc = 'lowercaseonly' ;
my $uc = 'UPPERCASEONLY' ;
my $numeric = '103204232' ;
my $allpunct = ')(#!@(^&#_*&^#;:<>' ;
my $oneofeach ='aA1!' ;
my $twoofeach ='aA1!Bb#2' ;

note( 'Deny_lc.') ;
my $Validator = String::Validator::Password->new(
	deny_lc => 1 , min_types => 0 , min_len => 0 ) ;
is ( $Validator->Check( $lc ), 1, 'lowercaseonly string  rejected.' ) ;
is ( $Validator->Check( $uc ), 0, 'UPPERCASEONLY string accepted.' ) ;
is ( $Validator->Check( $numeric ), 0, 'numeric string accepted.' ) ;
is ( $Validator->Check( $allpunct ), 0, 'allpunct string accepted.' ) ;
is ( $Validator->Check( $oneofeach ), 1, 'oneofeach string rejected.' ) ;
is ( $Validator->Check( $twoofeach ), 1, 'twoofeach string rejected' ) ;

note( 'Deny_uc.') ;
$Validator = String::Validator::Password->new(
	deny_uc => 1 , min_types => 0 , min_len => 0 ) ;
is ( $Validator->Check( $lc ), 0, 'lowercaseonly string  accepted.' ) ;
is ( $Validator->Check( $uc ), 1, 'UPPERCASEONLY string rejected.' ) ;
is ( $Validator->Check( $numeric ), 0, 'numeric string accepted.' ) ;
is ( $Validator->Check( $allpunct ), 0, 'allpunct string accepted.' ) ;
is ( $Validator->Check( $oneofeach ), 1, 'oneofeach string rejected.' ) ;
is ( $Validator->Check( $twoofeach ), 1, 'twoofeach string rejected' ) ;


note( 'Deny_nums.') ;
$Validator = String::Validator::Password->new(
	require_num => 1 , min_types => 0 , min_len => 0 ) ;
is ( $Validator->Check( $lc ), 1, 'lowercaseonly string  fails.' ) ;
is ( $Validator->Check( $uc ), 1, 'UPPERCASEONLY string fails.' ) ;
is ( $Validator->Check( $numeric ), 0, 'numeric string passes.' ) ;
is ( $Validator->Check( $allpunct ), 1, 'allpunct string fails.' ) ;
is ( $Validator->Check( $oneofeach ), 0, 'oneofeach string passes.' ) ;
is ( $Validator->Check( $twoofeach ), 0, 'twoofeach string passes' ) ;

note( 'Deny_punct.') ;
# This time change the parameters in the object directly,
# as this should work. If I had chosen to use Moose I would
# have gotten a free setter method, but I chose to skip
# the dependency and am not going to write the method.
$Validator->{ require_punct } = 1 ;
$Validator->{ require_num } = 0 ;
is ( $Validator->Check( $lc ), 1, 'lowercaseonly string  fails.' ) ;
is ( $Validator->Check( $uc ), 1, 'UPPERCASEONLY string fails.' ) ;
is ( $Validator->Check( $numeric ), 1, 'numeric string fails.' ) ;
is ( $Validator->Check( $allpunct ), 0, 'allpunct string passes.' ) ;
is ( $Validator->Check( $oneofeach ), 0, 'oneofeach string passes.' ) ;
is ( $Validator->Check( $twoofeach ), 0, 'twoofeach string passes' ) ;

note('Setting deny_xx to a value greater than 1 should set that as the maximum') ;
$Validator = String::Validator::Password->new(
	deny_num => 4 , min_types => 0 , min_len => 0 ) ;
is ( $Validator->Check( $numeric ), 1, 'num 4. numeric string rejected (10 digit). ' ) ;
is ( $Validator->Check( $twoofeach ), 0, 'num 4. twoofeach string accepted. (2 digit)' ) ;



done_testing();
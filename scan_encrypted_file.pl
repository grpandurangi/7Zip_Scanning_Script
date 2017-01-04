#!/usr/bin/perl -w
#Script to scan the 7z XML documents
#Author : gururaj.r.pandurangi@pwc.com

use File::Find;
use File::Copy;
use File::Basename;
use Cwd;

$XML_PATH = "/sftp/guestuser/incoming";
$SCAN_PATH = "/sftp/guestuser/decrypt";
$SCAN_FILE_FOLDER = "/sftp/guestuser/decrypt/scan";
$FINAL_PATH = "/sftp/guestuser/mulesoft"; 
$password = "myPass";
$command = "";
$mcafee_scan_cmd  = "/opt/isec/ens/threatprevention/bin/isecav";
$mcafee_task_name = "scan_xml_file";
$status = "";
$command = qx(which 7za 2>>/dev/null) ;

if ( "$?" != 0 )
 {
  die "Command for p7zip does not exist. Exiting \n";
 }
chomp($command);

if (! -e $mcafee_scan_cmd)
{ 

die "McAfee scan command $mcafee_scan_cmd does not exist. Exiting \n";

}  
#opendir(DIR, $XML_PATH);
#@files = grep(/\.7z$/,readdir(DIR));
#closedir(DIR);

if ( !-d $XML_PATH )
 {
  die "$XML_PATH does not exist\n";
 }

if ( !-d $SCAN_PATH )
 {
  die "$SCAN_PATH does not exist\n";
 }

if ( !-d $SCAN_FILE_FOLDER )
 {
  die "$SCAN_FILE_FOLDER does not exist\n";
 }

if ( !-d $FINAL_PATH )
 {
  die "$FINAL_PATH does not exist\n";
 }

# Function to scan a file 
sub mcafee_scan_a_file{
 
 my $status = "";
 system("$mcafee_scan_cmd --runtask --name $mcafee_task_name >>mcafee_output.log " );
 $status = qx($mcafee_scan_cmd --listtasks |grep $mcafee_task_name | awk '{print \$4}');

 while ($status ne "Completed" ) {
   system ("sleep 3");
   $status = qx($mcafee_scan_cmd --listtasks |grep $mcafee_task_name | awk '{print \$4}');
   chomp($status);
 }
 
 return $status ;

}

sub check_if_mcafee_ods_task_exists{

my $exists = "" ; 
$exists = qx($mcafee_scan_cmd --listtasks |grep $mcafee_task_name);

 if ( $exists eq "" ) {

 qx($mcafee_scan_cmd  --addodstask --name $mcafee_task_name --scanpaths $SCAN_FILE_FOLDER);
 print "McAfee task $mcafee_task_name has been added \n";

 } 


}

my @files;
find(
    {
        wanted => sub { push @files, $_ if -f $_ and /\.7z$/i },
        no_chdir => 1,
    },
    $XML_PATH
);

if (!@files) {
 print "No files for scan in $XML_PATH. Exiting\n"; 
 exit 0;
}

# First move all the files to decrypt folder
foreach $file (@files) {
  move($file, $SCAN_PATH) or die "Move $file -> $SCAN_PATH failed: $!";
  print "Encrypted file \"$file\" is moved to $SCAN_PATH \n";
}
print "---------------------File move completed----------------------------\n";
# Extract the 7zip file
# # Scan the file and move the sucess file to final folder
foreach $file (@files) {
  $filename = basename($file);
  $origfilename = $filename;
  $origfilename =~ s/.7z$//;
  #system("/usr/bin/7za" , "x" , "-p$password" , "$SCAN_PATH/$filename" , "-y" , "-o$SCAN_PATH" );
  system("$command x -p$password $SCAN_PATH/$filename -y -o$SCAN_FILE_FOLDER >>output.log " );
  
  if ( -e "$SCAN_FILE_FOLDER/$origfilename" ) {
   print "Extracted orginal file \"$origfilename\" from \"$filename\" successfully \n";
   }
  else  {
   print "File \"$filename\" was not extracted. Moving this file to issue folder \n"; 
   }

 #########################McAfee Command to scan the Orginal file####################
 check_if_mcafee_ods_task_exists();
 print "Scanning file \"$filename\" \n";
 $status = mcafee_scan_a_file();
 print "Scan status for file \"$filename\" is $status \n";
 #########################McAfee Command to scan the Orginal file####################
 
  if ( $status ne "Completed" ) {
       print "File \"$filename\" did NOT pass McAfee SCAN. Status: $status . Email notifcation sent.File is deleted.\n";
       unlink "$SCAN_PATH/$filename";
    }
     else 
    {
      print "\"$filename\" passed the McAfee SCAN and is moved to $FINAL_PATH \n";
      move ("$SCAN_PATH/$filename" , $FINAL_PATH ) or die "Move $filename -> $FINAL_PATH failed: $!";
    }
 unlink "$SCAN_FILE_FOLDER/$origfilename";
    print "-----------------------Completed $filename---------------------------\n";
}

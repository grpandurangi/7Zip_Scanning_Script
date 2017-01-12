#!/usr/bin/perl -w
#Script to scan the 7z XML documents
#Author : gururaj.r.pandurangi@pwc.com

use File::Find;
use File::Copy;
use File::Basename;
use MIME::Lite;
use Cwd;

$XML_PATH = "/sftp/guestuser/incoming";
$SCAN_PATH = "/sftp/guestuser/decrypt";
#$SCAN_FILE_FOLDER = "/sftp/guestuser/decrypt/scan";
$FINAL_PATH = "/sftp/guestuser/mulesoft"; 
$password = "myPass";
$command = "";
$status = "";
$command = qx(which 7za 2>>/dev/null) ;
$email_notification_list = "grpandurangi\@gmail.com";
$from_email = "scanreport\@myapplication.com";
$log_folder = "/var/log";
$oas_log = "/opt/isec/ens/threatprevention/var/isecoasmgr.log" ;

if ( "$?" != 0 )
 {
  die "Command for p7zip does not exist. Exiting \n";
 }
chomp($command);

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

if ( !-d $FINAL_PATH )
 {
  die "$FINAL_PATH does not exist\n";
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

foreach $file (@files) {

  $filename = basename($file);
  $origfilename = $filename;
  $origfilename =~ s/.7z$//;

  my $date = qx (date +%Y%m%d%H%M%S); 
  chomp($date);
  my $folder = "$filename#_#$date";

  $SCAN_FILE_FOLDER = "$SCAN_PATH/$folder";
  unless(-e $SCAN_FILE_FOLDER or mkdir $SCAN_FILE_FOLDER) {
        die "Unable to create $SCAN_FILE_FOLDER\n";
    }  
 
  system("$command x -p$password $SCAN_PATH/$filename -y -o$SCAN_FILE_FOLDER >>$log_folder/decrypt_output.log " );
  system ("sleep 2"); 

  # Check if the file exists 
  qx( ls -1 "$SCAN_FILE_FOLDER/$origfilename" >/dev/null 2>/dev/null );
  if ( "$?" == 0 ) {
   print "Extracted orginal file \"$origfilename\" from \"$filename\" successfully \n";
   $status = "Completed";
   }
  else  {
   print "Original file for \"$filename\" does not exist. \n"; 
   $status = "Infected";

  system("rm -rf $SCAN_FILE_FOLDER");

  # If McAfeeVSEForLinux is installed
    my $mfl_rpm_installed = "";
    $mfl_rpm_installed = qx ( rpm -qa McAfeeVSEForLinux );
    chomp($mfl_rpm_installed);
     if ( $mfl_rpm_installed ne "" ) {
              print "Print $mfl_rpm_installed \n";  
              #$output  = qx( grep $folder /var/log/messages | awk -F "#_#" '{print \$1}' | head -1 | awk -F "/" '{print \$NF}' );
              @output  = qx( grep $folder /var/log/messages);
              $message = $output[0];
        }
 # If ISec is installed
     my $isec_rpm_installed  = "";
      $isec_rpm_installed  = qx (rpm -qa ISecESP);
      chop($isec_rpm_installed);
   if ( $isec_rpm_installed ne "" ) {
              print "Print $isec_rpm_installed";
              #@output  = qx( grep $folder $oas_log | awk -F "#_#" '{print \$1}' |awk -F "/" '{print \$NF}');
              @output  = qx( grep $folder $oas_log );
              $message = $output[0];
        }

 }

  if ( $status ne "Completed" ) {
       print "File \"$filename\" did NOT pass McAfee SCAN. Status: $status . Email notifcation sent.File is deleted.\n";
         my $subject = "McAfee scan for $filename with status: $status";
         $msg = MIME::Lite->new(
                 From     => $from_email,
                 To       => $email_notification_list,
                 Subject  => $subject,
                 Data     => $message
                 );

          $msg->attr("content-type" => "text/html");
          $msg->send;

       unlink "$SCAN_PATH/$filename";
    }
     else 
    {
      print "\"$filename\" passed the McAfee SCAN and is moved to $FINAL_PATH \n";
      move ("$SCAN_PATH/$filename" , $FINAL_PATH ) or die "Move $filename -> $FINAL_PATH failed: $!";
    }
      unlink "$SCAN_FILE_FOLDER/$origfilename";
    print "-----------------------$status $filename---------------------------\n";
}

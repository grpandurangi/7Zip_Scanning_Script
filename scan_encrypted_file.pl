#!/usr/bin/perl
#Script to scan the 7z XML documents
#
#Author : gururaj.r.pandurangi@pwc.com

use File::Find;
use File::Copy;
use File::Basename;
use Cwd;

$XML_PATH = "/sftp/guestuser/incoming";
$SCAN_PATH = "/sftp/guestuser/decrypt";
$FINAL_PATH = "/sftp/guestuser/mulesoft"; 
$password = "myPass";
$scanexitcode = "1";

#opendir(DIR, $XML_PATH);
#@files = grep(/\.7z$/,readdir(DIR));
#closedir(DIR);

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


# Extract the 7zip file
# # Scan the file and move the sucess file to final folder
foreach $file (@files) {
  move($file, $SCAN_PATH) or die "Move $file -> $SCAN_PATH failed: $!";
  $filename = basename($file);
  print "Encrypted file \"$filename\" is moved to $SCAN_PATH \n";
  $origfilename = $filename;
  $origfilename =~ s/.7z$//;
  #system("/usr/bin/7za" , "x" , "-p$password" , "$SCAN_PATH/$filename" , "-y" , "-o$SCAN_PATH" );
  system("/usr/bin/7za x -p$password $SCAN_PATH/$filename -o$SCAN_PATH >>output.log " );
  
  if ( -e "$SCAN_PATH/$origfilename" ) {
   print "Extracted orginal file \"$origfilename\" from \"$filename\" successfully \n";
   }
  else  {
   print "File \"$filename\" was not extracted. Moving this file to issue folder \n"; 
   }

  #########################McAfee Command to scan the Orginal file####################
  #
  #
  #########################McAfee Command to scan the Orginal file####################

  #$scanexitcode = $?;
  if ( $scanexitcode != 0 ) {
       print "File \"$filename\" did NOT pass McAfee SCAN. Exit code: $scanexitcode. Email notifcation sent.File is deleted.\n";
       unlink "$SCAN_PATH/$filename";
    }
     else 
    {
      print "\"$filename\" passed the McAfee SCAN and is moved to $FINAL_PATH \n";
      move ("$SCAN_PATH/$filename" , $FINAL_PATH ) or die "Move $filename -> $FINAL_PATH failed: $!";
    }
 unlink "$SCAN_PATH/$origfilename";
}

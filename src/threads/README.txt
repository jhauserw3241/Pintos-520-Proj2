To add the alarm-mega test, I modified the below files:
 - Created the alarm-mega.ck file
 	This file was created to call the alarm 70 times.
 - Updated tests.c
 	This file was modified to incorportate the alarm-mega command into the list of acceptable commands.
 - Updated tests.h
 	This file was modified to add the variable name for the alarm-mega command.
 - Updated alarm-wait.c
 	This file was modified to have the program sleep while pintos prints out the alarm output.
 - Updated Make.tests
 	This file was modified to see the alarm-mega file.
 - Updated Rubric.alarm
 	This file was modified to see the alarm-mega command.

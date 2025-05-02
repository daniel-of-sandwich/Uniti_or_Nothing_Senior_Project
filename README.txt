Run command on time interval

Linux:

1. Run "crontab -e".
2. Select text editor if prompted, [1] works.
3. Add to the bottom of the file without quotes: "*/30 * * * * <command>", replacing <command> with what you want to run.
^ This runs <command> every 30 minutes. For more info, check https://crontab.guru/.

Windows:

1. Run "taskschd.msc /s" or open "Task Scheduler" from search bar.
2. Under "Action" tab, click "Create Basic Task".
3. Enter a name and description. The name is what the service will be called in Task Manager, Services, etc. Next.
4. For when the task should start, select "When the computer starts". The every 30 minutes bit is in advanced settings after the task is created. Next.
5. Select "Start a program". Next.
6. Enter the program command, arguments, and starting directory. For testing I just put "calc" (Calculator) in "Program/script" and left the other two blank. Next.
7. At the bottom, check the box that starts with "Open the Properties dialog ...". Finish.
8. The Properties tab should now be open. Navigate to the "Triggers" tab. Select the only row and click "Edit...".
9. Under "Advanced settings", check the option begining with "Repeat task every:". Set task to repeat every "30 minutes" for a duration of "Indefinitely". OK.
^ This runs the inputted command every 30 minutes. No source for this one, I just played with the GUI.

rule SchTasks {
  strings:
      $test = /SchTasks.exe\ .*/ nocase

  condition:
      any of them
  }

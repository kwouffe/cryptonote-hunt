rule IRCBot {
  strings:
      $test = /\$server.*\ unless/ nocase

  condition:
      any of them
  }

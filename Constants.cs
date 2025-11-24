namespace Elite_Dangerous_Addon_Launcher_V2
{
    /// <summary>
    /// Central constants for the application
    /// </summary>
    public static class AppConstants
    {
        // File and directory constants
        public const string ProfilesFileName = "profiles.json";
        public const string SettingsFileName = "settings.json";

        // Executable names
        public const string EdLaunchExe = "edlaunch.exe";
        public const string TargetGuiExe = "targetgui.exe";
        public const string VoiceAttackProcessName = "VoiceAttack";
        public const string EliteDangerousOdysseyHelperName = "Elite Dangerous Odyssey Materials Helper";

        // Command-line arguments
        public const string ProfileArgumentPrefix = "/profile=";
        public const string AutoLaunchArgument = "/autolaunch";

        // Profile names and IDs
        public const string DefaultProfileName = "Elite Dangerous";
        public const string LegendaryGameAlias = "elite";
        public const string LegendaryGameId = "9c203b6ed35846e8a4a9ff1e314f6593";

        // Theme constants
        public const string DarkTheme = "Dark";
        public const string LightTheme = "Light";
        public const string DefaultTheme = "Light";

        // Path constants
        public const string EpicManifestPath = @"C:\ProgramData\Epic\EpicGamesLauncher\Data\Manifests";

        // Legendary constants
        public const string LegendaryDefaultParams = "/edh /autorun /autoquit";
        public const string LegendaryCommand = "legendary";
        public const string LegendaryLaunchCommand = "launch elite";

        // Window constants
        public const double DefaultMinWindowHeight = 300;
        public const double DefaultMaxWindowHeight = 800;
        public const double DefaultHeaderHeight = 150;
        public const double DefaultFooterHeight = 50;
        public const double DefaultRowHeight = 48;

        // Process handling constants
        public const int ProcessWaitTimeoutMs = 5000;
        public const int MaxEdLaunchRetries = 20;
        public const int EdLaunchRetryDelayMs = 500;

        // Steam URLs
        public const string SteamRunGameIdFormat = "steam://rungameid/359320";
        public const string EpicLaunchFormat = "epic://launch";

        // Error messages
        public const string LegendaryNotFoundMessage = "Elite Dangerous is installed via Epic Games, but 'legendary' not found in PATH.\n" +
            "Please install it from https://github.com/derrod/legendary to enable Epic support.";
        public const string EdLaunchNotFoundMessage = "edlaunch.exe was not found on your computer. Please add it manually.";
    }
}

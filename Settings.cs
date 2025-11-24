namespace Elite_Dangerous_Addon_Launcher_V2
{
    public class Settings
    {
        #region Public Properties

        public bool CloseAllAppsOnExit { get; set; } = false;

        private string _theme = AppConstants.DefaultTheme;
        public string Theme
        {
            get => _theme;
            set => _theme = value ?? AppConstants.DefaultTheme;
        }

        #endregion Public Properties
    }
}
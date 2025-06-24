namespace SigcheckGUI
{
    public class YaraRule
    {
        public bool Enabled { get; set; }
        public string RulePath { get; set; }
        public string Description { get; set; }
        public string Name { get; set; }
        public string RawText { get; set; }
        public string Error { get; set; }
        public bool Matched { get; set; }

        public YaraRule Clone()
        {
            return new YaraRule
            {
                Enabled = this.Enabled,
                RulePath = this.RulePath,
                Description = this.Description,
                Name = this.Name,
                RawText = this.RawText,
                Error = this.Error,
                Matched = this.Matched
            };
        }
    }
} 
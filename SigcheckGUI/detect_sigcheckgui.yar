rule Detect_SigcheckGUI_Exe
{
    meta:
        description = "Срабатывает на exe-файл SigcheckGUI"
        date = "2024-06-23"
    strings:
        $name = "SigcheckGUI" ascii wide
    condition:
        $name
} 
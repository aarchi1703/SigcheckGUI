   M S B A M L   `   `   `  ���� F  BSigcheckGUI, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null)clr-namespace:SigcheckGUISigcheckGUI      SigcheckGUI.MainWindow   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     +localclr-namespace:SigcheckGUI       � Title$  Sigcheck GUI��$	��820��$
��1350�� � WindowStartupLocation$ CenterScreen=� J� 	AllowDrop .  � 	Resources    LinkButtonStyle �� 
TargetType �� Property �� Value �� 
TargetType �� Triggers	 P� Property
 P� Value��%  &	        �� " ��.���  � ��
 ���� ��  � ��$ 0q���  � �� �#0078D7��  �@�Cursor$
 Hand����  � �� �� " ��.R��� #��z��$��	Underline{�#��z�� P� 	 �@J�IsMouseOver
 . . ���  � �� �#005A9E.���  � ColumnDefinitions �� $
��Auto ��� $��* � � RowDefinitions �� $
��Auto ��� $��* ��� $
��Auto �.+��� $��0��$��2��$��0�����	#FF0078D7 �� Padding$ 10q� �� CornerRadius$ 5�� J� Effect 3  -System.Windows.Media.Effects.DropShadowEffect     ShadowDepth$ 1Q�   	Direction$	 270Q�   Color$ 	LightGray��   Opacity$	 0.5Q�   
BlurRadius$ 5Q�._���  �� Orientation$ 
Horizontal=�$��5q�.+��� $��Selected File:��
�������$��Center=�$��0,0,10,0q�$��14(�$
��Bold"��� -    ��Name$ labelSelectedFile��
�������$��Center=�$
��Wrap=�$��14(��� -    ��Name$ tabControlResults��$��0��$��1�� �� TabStripPlacement$
 Left=�$	��150��$��0q�
������ $��	10,0,0,10q�  ��Name �� Triggers �� 
TargetName �� Value �� Binding �� RelativeSource �� Path  �� TextAlignment��%�  '��       �� " ��.���  � ��$ 15,10q���  � ��
 ���� ��  � ��$ 0q���  � ��$ 0,2,0,2q���  � ��$ Stretch=���  � �� �� " ��.R��� $��Border��#��z��#��z��#��z��$ 5��#��z��._��� $ ContentSite��$��Center=�$
��Left=�$��Header��#��z�� P� 	 �@��
IsSelected
 . . ��� $ Border�� � �� �	#FF0078D7��  � ��
 �����P� 	 �@��
IsSelected
 .  . ��� $ Border�� � ��
 �������  � ��
 �   �P� 	 �@J�IsMouseOver
 . . ��� $ Border�� � �� �#E0E0E0�� $
 True�� ��  �� *Self+$	 Tag�.a��� $ Border�� � ��
 �������  � �� �� .R��� $
��Wrap=�$
  Left=�$��12(�$��SemiBold"����� .@��� $��All Info (-a)���� $��Catalog Content (-d)���� $��Hashes (-h)���� $��Manifest (-m)���� $��Version Number (-n)���� $��VirusTotal (-v)���� $��Энтропия���� $
��YARA��.���  �� $	��220 ��� $��* �.+��� -   ! ��Name$! listYaraRules��$��0��$��0,0,10,0q��� $��1��$��0q�.+��� $1��+Исходный текст правила:��$
��Bold"�$��0,0,0,5q��� -   " ��Name$" textYaraRuleContent��$��Consolas)�$��13(�# �� AcceptsReturn# . "$ �� VerticalScrollBarVisibility$
$ Auto=�$% �� HorizontalScrollBarVisibility$
% Auto=�& �� 
IsReadOnly& . $	��320���� -   $ textYaraRuleError��
���  ��$
��Bold"�$��0,10,0,0q�$y�	Collapsed=��� $��История��� $��1��$��1��$��5q� �� $��* ��� $
��Auto �.+��� $��0��$	��600��
�������$ 10q�$ 5��   $ 1Q�$	 270Q�$ 	LightGray��$	 0.5Q�$ 5Q�._��� -   ' ��Name$' contentPresenter��$��0q����� *SelectedItem.Content+( �� ElementName$( tabControlResults���� $��1��$��0,10,0,0q�$ 10q�
�������$ 5��   $ 1Q�$	 270Q�$ 	LightGray��$	 0.5Q�$ 5Q�._��  �� $
��Auto ��� $��* ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto ��� $
��Auto � �� $
��Auto �.+��� $ 
Horizontal=�$��0��$��Center=�.+��� -   ) ��Name$) checkBoxRParam��$-��'Рекурсивная проверка��$��0,0,15,0q�$��Center=��� -   $) checkBoxSParam��$#��Проверка отзыва��$��0,0,15,0q�$��Center=��� -	   * ��Name$* buttonRefresh��$��Обновить��$��2��$��5q�  MainMenuButtonStyle#��[ �� -
   $* 
buttonFile��$��Выбрать файл��$��3��$��5q�#��[ �� -   $* buttonSaveReport��$#��Сохранить отчет��$��4��$��5q�#��[ �� -   $* buttonSaveReportRu��$,��&Сохранить на русском��$��5��$��5q�#��[ �� -   $* buttonClearHistory��$%��Очистить историю��$��6��$��5q�#��[ �� -   $* buttonSettings��$��Настройки��$��7��$��5q�#��[ 
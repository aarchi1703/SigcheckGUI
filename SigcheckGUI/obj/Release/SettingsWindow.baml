   M S B A M L   `   `   `  ���� F  BSigcheckGUI, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null)clr-namespace:SigcheckGUISigcheckGUI  O Kmscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e0891&clr-namespace:System;assembly=mscorlibSystem      SigcheckGUI.SettingsWindow   R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     +localclr-namespace:SigcheckGUI     6sys&clr-namespace:System;assembly=mscorlib       � Title$-  'Настройки оповещений��$	��700��$
��1000�� � WindowStartupLocation$ CenterScreen=����#F5F5F5 � 	Resources    GroupHeaderStyle �� 
TargetType �� Property �� Value  SettingCardStyle3  -System.Windows.Media.Effects.DropShadowEffect   
BlurRadius   ShadowDepth   Opacity  SettingDescriptionStyle  SettingsButtonStyle	 �� Triggers
 P� Property P� Value �� Type  VersionFormats��%B  &	        &	 w     &	 a    &	 �    &	 �    �� " ��.���  � ��$ 18(���  � ��$ SemiBold"���  � ��$ 0,0,0,10q���  � �� �#333333�� " ��.���  � ��
 �������  � ��$ 1q���  � �� �#E0E0E0��  �@��CornerRadius$ 4����  �@��Padding$ 16q���  � ��$ 0,0,0,16q���  �@J�Effect   $ 10Q�$ 1Q�$	 0.1Q��� " ��.���  � ��$ 12(���  � �� �#666666��  � ��$ 0,4,0,0q��� " ��.���  � ��$ 14(���  � ��$ SemiBold"���  � ��$
 10,5q���  � �� �#007BFF��  � ��
 �������  � ��$ 0q���  �@J�Effect   $ 10Q�$ 1Q�$	 0.1Q�	 P� 
 �@J�IsMouseOver . . ���  � �� �#0056B3�� " ��.s���X.X.X.X����	X.X.X����X.X��.��� $��16q� � RowDefinitions �� $
��Auto ��� $��* ��� $
��Auto ��� $
��Auto �.+��� $��0��$-��'Настройки оповещений��#��[  $��0,0,0,16q��� $��1��$
��Auto=�$��0,0,0,16q�.���� .+��� -    ��Name$ settingsItemsControl������ .R��� #��[ ._��  �� $
��Auto ��� $
��Auto �.+��� $��0��#��[  ���� *	GroupName+�� $��1������ *
Settings+���� .R�� $	��0,8q� � ColumnDefinitions �� $
��Auto ��� $��* ��� $
��Auto �.+��� -   $��0��$��Center=�$��0,0,16,0q� d� 	IsChecked �� *	Enabled+�� $��1��.+��� $��SemiBold"����� *	Parameter+�� #��[ ���� *Description+�� -   $��2��$	��150��$��16,0,0,0q����� *Value+ �� Mode$ TwoWay=�.������ " ��.���  � y�$ Visible=�	 ��  �� Binding �� *	Parameter+ �� Value Verified.a���  � y�$ 	Collapsed=���  �� *	Parameter+ 	Publisher.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Comments.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Company.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Description.a���  � y�$ 	Collapsed=���  �� *	Parameter+ File version.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Prod version.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Binary Version.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Original Name.a���  � y�$ 	Collapsed=���  �� *	Parameter+ Internal Name.a���  � y�$ 	Collapsed=�.���� -   $��2�� �� 
IsEditable . $	��150��$��16,0,0,0q�#��[  �� SelectedValuePath$ .�� �� Text �� *Value+$ TwoWay=� �� SelectedValue �� *Value+$ TwoWay=����� " ��.���  � y�$ 	Collapsed=�	 ��  �� *	Parameter+ File version.a���  � y�$ Visible=���  �� *	Parameter+ Prod version.a���  � y�$ Visible=���  �� *	Parameter+ Binary Version.a���  � y�$ Visible=��� #��[ $��0,0,0,16q�._��� .+��� $��YARA-правила��#��[  �� $����Добавьте пути к вашим YARA-правилам. Каждый активный файл будет использоваться при проверке.��#��[ $��0,0,0,8q�� $��0,0,0,8q� �� $��* ��� $
��Auto ��� $
��Auto �.+��� $��0�����#E0E0E0$��1q� �� CornerRadius$ 4��
������� �� Padding$	 6,2q�$��0,0,8,0q�._��� -    ��Name$ textBoxYaraFolderPath��$��Center=�$��0q�
������  �� 
IsReadOnly .  �� -   $��1��$��
Обзор��#��[ $	��100��$��32��$��0,0,8,0q��� -   $��2��$��Очистить��#��[ $	��100��$��32��� $��0,0,0,8q� �� $��* ��� $
��Auto ��� $
��Auto �.+��� $��0�����#E0E0E0$��1q�$ 4��
�������$	 6,2q�$��0,0,8,0q�._��� -   $ textBoxGithubYaraPath��$��Center=�$��0q�
������  .  �� -	   $��1��$��Загрузить��#��[ $	��100��$��32��$��0,0,8,0q��� -
   $��2��$��Очистить��#��[ $	��100��$��32���� -   $ yaraRulesItemsControl������ .R�� $	��0,8q� �� $
��Auto ��� $��* ��� $
��Auto ��� $
��Auto �.+��� $��0��$��Center=�$��0,0,16,0q� �� *	Enabled+�� $��1�����#E0E0E0$��1q�$ 4��
�������$	 6,2q�$��0,0,16,0q�._��� $��Center=�$��CharacterEllipsis=����� *
RulePath+�� -   $��2��$��Выбрать файл��#��[ $��0,0,8,0q�$	��130��$��32��
 � Tag �� �� -   $��3��$��Удалить��#��[  �� ��  �� Orientation$ 
Horizontal=�$��0,8,0,0q�.+��� -   $%��Добавить правило��#��[ �� #��[ $��0,0,0,16q�._��� .+��� $'��!Настройки истории��#��[  �� $����Если включено, при восстановлении файла из истории будут применены настройки алармов и YARA-правил, которые были активны на момент обработки файла. В противном случае, восстановятся только данные на вкладках, а текущие настройки приложения останутся без изменений.��#��[ $��0,0,0,8q��� -    ��Name$- 'checkBoxEnableIndividualHistorySettings��$���{Использовать индивидуальные настройки для восстановленных файлов��$��0,8,0,0q��� -    ��Name$ labelYaraLoading��$�� ��
����  �$
��Bold"�$��0,0,0,8q�� $��3��$��0,20,0,0q� �� $
��Auto ��� $��* �.+��� -     ��Name$  buttonResetToDefaults��$��0��$*��$Сброс к стандартным��$��0,0,10,0q�$
��Left=�#��[ �� $ 
Horizontal=�$��1��$��Right=�.+��� -   $  	btnCancel��$��Отмена��$��0,0,10,0q�#��[ �� -   $  btnSave��$��Сохранить��#��[ �� -   $*��$Удалить все правила��#��[ $��
20,0,582,0q�$��1��$��162.1��$��33.62��
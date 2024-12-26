// qt-install-script.qs
function Controller() {
    installer.setAutomatedPageStatus(QInstaller.Introduction, QInstaller.AcceptLicense);
    installer.setAutomatedPageStatus(QInstaller.TargetDirectory, "C:\\Qt");
    installer.setAutomatedPageStatus(QInstaller.ComponentSelection, "qt.qt6.653.win64_msvc2019_64");
    installer.setAutomatedPageStatus(QInstaller.ReadyForInstallation, QInstaller.ClickButton);
}

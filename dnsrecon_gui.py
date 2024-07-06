import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QCheckBox, QComboBox, QTextEdit, QSpinBox, QMessageBox, QFileDialog

class DNSReconApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('DNSRecon GUI')
        self.setGeometry(100, 100, 600, 600)

        layout = QVBoxLayout()

        formLayout = QFormLayout()

        self.domainInput = QLineEdit(self)
        formLayout.addRow('Domain:', self.domainInput)

        self.nsServerInput = QLineEdit(self)
        formLayout.addRow('Name Server:', self.nsServerInput)

        self.rangeInput = QLineEdit(self)
        formLayout.addRow('IP Range:', self.rangeInput)

        self.dictionaryInput = QLineEdit(self)
        dictionaryButton = QPushButton('Select Dictionary File', self)
        dictionaryButton.clicked.connect(self.selectDictionaryFile)
        formLayout.addRow(dictionaryButton, self.dictionaryInput)

        self.filterCheckBox = QCheckBox('Filter out wildcard IP addresses', self)
        formLayout.addRow(self.filterCheckBox)

        self.axfrCheckBox = QCheckBox('Perform AXFR with standard enumeration', self)
        formLayout.addRow(self.axfrCheckBox)

        self.reverseCheckBox = QCheckBox('Perform reverse lookup of IPv4 ranges in the SPF record', self)
        formLayout.addRow(self.reverseCheckBox)

        self.bingCheckBox = QCheckBox('Perform Bing enumeration', self)
        formLayout.addRow(self.bingCheckBox)

        self.yandexCheckBox = QCheckBox('Perform Yandex enumeration', self)
        formLayout.addRow(self.yandexCheckBox)

        self.crtCheckBox = QCheckBox('Perform crt.sh enumeration', self)
        formLayout.addRow(self.crtCheckBox)

        self.whoisCheckBox = QCheckBox('Perform deep whois record analysis', self)
        formLayout.addRow(self.whoisCheckBox)

        self.dnssecCheckBox = QCheckBox('Perform DNSSEC zone walk', self)
        formLayout.addRow(self.dnssecCheckBox)

        self.threadsInput = QSpinBox(self)
        self.threadsInput.setRange(1, 100)
        self.threadsInput.setValue(10)
        formLayout.addRow('Threads:', self.threadsInput)

        self.lifetimeInput = QSpinBox(self)
        self.lifetimeInput.setRange(1, 10)
        self.lifetimeInput.setValue(3)
        formLayout.addRow('Lifetime:', self.lifetimeInput)

        self.tcpCheckBox = QCheckBox('Use TCP protocol', self)
        formLayout.addRow(self.tcpCheckBox)

        self.dbInput = QLineEdit(self)
        dbButton = QPushButton('Select DB Output File', self)
        dbButton.clicked.connect(self.selectDBFile)
        formLayout.addRow(dbButton, self.dbInput)

        self.xmlInput = QLineEdit(self)
        xmlButton = QPushButton('Select XML Output File', self)
        xmlButton.clicked.connect(self.selectXMLFile)
        formLayout.addRow(xmlButton, self.xmlInput)

        self.csvInput = QLineEdit(self)
        csvButton = QPushButton('Select CSV Output File', self)
        csvButton.clicked.connect(self.selectCSVFile)
        formLayout.addRow(csvButton, self.csvInput)

        self.jsonInput = QLineEdit(self)
        jsonButton = QPushButton('Select JSON Output File', self)
        jsonButton.clicked.connect(self.selectJSONFile)
        formLayout.addRow(jsonButton, self.jsonInput)

        self.iwCheckBox = QCheckBox('Continue brute forcing even if a wildcard record is discovered', self)
        formLayout.addRow(self.iwCheckBox)

        self.disableRecursionCheckBox = QCheckBox('Disable check for recursion on name servers', self)
        formLayout.addRow(self.disableRecursionCheckBox)

        self.disableBindCheckBox = QCheckBox('Disable check for BIND version on name servers', self)
        formLayout.addRow(self.disableBindCheckBox)

        self.verboseCheckBox = QCheckBox('Enable verbose', self)
        formLayout.addRow(self.verboseCheckBox)

        self.typeComboBox = QComboBox(self)
        self.typeComboBox.addItems(['std', 'rvl', 'brt', 'srv', 'axfr', 'bing', 'yand', 'crt', 'snoop', 'tld', 'zonewalk'])
        formLayout.addRow('Type:', self.typeComboBox)

        self.outputText = QTextEdit(self)
        layout.addLayout(formLayout)

        buttonLayout = QVBoxLayout()

        self.runButton = QPushButton('Run DNSRecon', self)
        self.runButton.clicked.connect(self.runDNSRecon)
        buttonLayout.addWidget(self.runButton)

        self.clearButton = QPushButton('Clear Output', self)
        self.clearButton.clicked.connect(self.clearOutput)
        buttonLayout.addWidget(self.clearButton)

        self.previewButton = QPushButton('Preview Command', self)
        self.previewButton.clicked.connect(self.previewCommand)
        buttonLayout.addWidget(self.previewButton)

        layout.addLayout(buttonLayout)
        layout.addWidget(self.outputText)

        self.setLayout(layout)

    def selectDictionaryFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Select Dictionary File", "", "All Files (*);;Text Files (*.txt)", options=options)
        if fileName:
            self.dictionaryInput.setText(fileName)

    def selectDBFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Select SQLite DB File", "", "All Files (*);;Database Files (*.db)", options=options)
        if fileName:
            self.dbInput.setText(fileName)

    def selectXMLFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Select XML Output File", "", "XML Files (*.xml);;All Files (*)", options=options)
        if fileName:
            self.xmlInput.setText(fileName)

    def selectCSVFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Select CSV Output File", "", "CSV Files (*.csv);;All Files (*)", options=options)
        if fileName:
            self.csvInput.setText(fileName)

    def selectJSONFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Select JSON Output File", "", "JSON Files (*.json);;All Files (*)", options=options)
        if fileName:
            self.jsonInput.setText(fileName)

    def buildCommand(self):
        command = ['dnsrecon']

        if self.domainInput.text():
            command.extend(['-d', self.domainInput.text()])

        if self.nsServerInput.text():
            command.extend(['-n', self.nsServerInput.text()])

        if self.rangeInput.text():
            command.extend(['-r', self.rangeInput.text()])

        if self.dictionaryInput.text():
            command.extend(['-D', self.dictionaryInput.text()])

        if self.filterCheckBox.isChecked():
            command.append('-f')

        if self.axfrCheckBox.isChecked():
            command.append('-a')

        if self.reverseCheckBox.isChecked():
            command.append('-s')

        if self.bingCheckBox.isChecked():
            command.append('-b')

        if self.yandexCheckBox.isChecked():
            command.append('-y')

        if self.crtCheckBox.isChecked():
            command.append('-k')

        if self.whoisCheckBox.isChecked():
            command.append('-w')

        if self.dnssecCheckBox.isChecked():
            command.append('-z')

        if self.threadsInput.value():
            command.extend(['--threads', str(self.threadsInput.value())])

        if self.lifetimeInput.value():
            command.extend(['--lifetime', str(self.lifetimeInput.value())])

        if self.tcpCheckBox.isChecked():
            command.append('--tcp')

        if self.dbInput.text():
            command.extend(['--db', self.dbInput.text()])

        if self.xmlInput.text():
            command.extend(['-x', self.xmlInput.text()])

        if self.csvInput.text():
            command.extend(['-c', self.csvInput.text()])

        if self.jsonInput.text():
            command.extend(['-j', self.jsonInput.text()])

        if self.iwCheckBox.isChecked():
            command.append('--iw')

        if self.disableRecursionCheckBox.isChecked():
            command.append('--disable_check_recursion')

        if self.disableBindCheckBox.isChecked():
            command.append('--disable_check_bindversion')

        if self.verboseCheckBox.isChecked():
            command.append('-v')

        if self.typeComboBox.currentText():
            command.extend(['-t', self.typeComboBox.currentText()])

        return command

    def previewCommand(self):
        command = self.buildCommand()
        QMessageBox.information(self, "Command Preview", ' '.join(command))

    def runDNSRecon(self):
        command = self.buildCommand()
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            self.outputText.setPlainText(stdout.decode() + stderr.decode())
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def clearOutput(self):
        self.outputText.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = DNSReconApp()
    ex.show()
    sys.exit(app.exec_())

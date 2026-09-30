"""Офлайн-просмотр зашифрованного резервного файла, без входа в рабочую БД."""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem,
    QFileDialog, QInputDialog, QLineEdit, QMessageBox, QAbstractItemView,
)
from auth.emergency import decrypt_vault


def show_recovery(parent=None):
    path, _ = QFileDialog.getOpenFileName(parent, 'Открыть зашифрованный резервный файл', '', 'JSON (*.json)')
    if not path:
        return
    phrase, ok = QInputDialog.getText(parent, 'Расшифрование', 'Парольная фраза резервного файла:', QLineEdit.Password)
    if not ok:
        return
    try:
        data = decrypt_vault(path, phrase)
    except (ValueError, OSError) as exc:
        QMessageBox.warning(parent, 'Не удалось открыть файл', str(exc))
        return
    dialog = QDialog(parent)
    dialog.setWindowTitle('Резервные пароли — конфиденциально')
    dialog.resize(1050, 430)
    layout = QVBoxLayout(dialog)
    note = QLabel('Пароли из выбранного набора. Они вступают в силу только после команды «компрометация».\n'
                  'Не передавайте файл и парольную фразу вместе. При копировании очистите буфер обмена после входа.')
    note.setWordWrap(True)
    layout.addWidget(note)
    table = QTableWidget(len(data['accounts']), 2)
    table.setHorizontalHeaderLabels(['Логин', 'Резервный пароль (50 символов)'])
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectItems)
    for i, account in enumerate(data['accounts']):
        table.setItem(i, 0, QTableWidgetItem(str(account['login'])))
        table.setItem(i, 1, QTableWidgetItem(str(account['password'])))
    table.resizeColumnsToContents()
    layout.addWidget(table)
    # Qt table does not copy by default: explicit Copy action on selected cell.
    from PyQt5.QtWidgets import QPushButton, QApplication
    copy = QPushButton('Копировать выбранную ячейку')
    copy.clicked.connect(lambda: QApplication.clipboard().setText(table.currentItem().text()) if table.currentItem() else None)
    layout.addWidget(copy)
    dialog.exec_()
    table.clearContents()
    data.clear()

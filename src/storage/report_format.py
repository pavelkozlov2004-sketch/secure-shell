"""Headless report format shared by conversion, storage, and Qt rendering."""

FORMAT = 'secure-shell-table-v1'
MAX_TABLE_BYTES = 1024 * 1024
MAX_WIDGET_ROWS = 400
COLUMNS = (
    ('№', 42), ('Код', 58), ('Описание объекта', 245), ('Местоположение', 175),
    ('Участок', 115), ('А', 74), ('Б', 74), ('В', 74), ('Г', 74),
    ('Количество', 92), ('Время', 92), ('Ответственный', 145), ('Примечание', 195),
)
MERGE_COLUMNS = (2, 3, 4, 9, 10, 11, 12)


EXAMPLE_REPORT = {
    'format': FORMAT,
    'title': 'СВОДНАЯ ВЕДОМОСТЬ',
    'subtitle': 'Демонстрационный образец оформления таблицы',
    'sections': [
        {'title': 'Раздел 1 — плановые записи', 'groups': [
            {'title': 'Северный участок', 'rows': [
                ['1', 'A-01', 'Техническое помещение', 'Корпус 1, этаж 2', 'Сектор А',
                 '12', '18', '—', '—', '4', '09:00', 'Иванов', 'Плановый осмотр'],
                ['2', 'A-02', 'Техническое помещение', 'Корпус 1, этаж 2', 'Сектор А',
                 '14', '20', '—', '—', '4', '09:00', 'Иванов', 'Плановый осмотр'],
                ['3', 'A-03', 'Техническое помещение', 'Корпус 1, этаж 2', 'Сектор А',
                 '16', '22', '—', '—', '4', '09:00', 'Иванов', 'Плановый осмотр'],
                ['4', 'A-04', 'Техническое помещение', 'Корпус 1, этаж 2', 'Сектор А',
                 '18', '24', '—', '—', '4', '09:00', 'Иванов', 'Плановый осмотр'],
            ]},
            {'title': 'Южный участок', 'rows': [
                ['5', 'B-01', 'Склад материалов', 'Корпус 2', 'Сектор Б',
                 '7', '11', '13', '15', '2', '11:30', 'Петров', 'Подготовка'],
                ['6', 'B-02', 'Склад материалов', 'Корпус 2', 'Сектор Б',
                 '8', '12', '14', '16', '2', '11:30', 'Петров', 'Подготовка'],
            ]},
        ], 'summary': 'Итого по разделу: 6 записей'},
        {'title': 'Раздел 2 — завершённые записи', 'groups': [
            {'title': 'Центральный участок', 'rows': [
                ['7', 'C-01', 'Архивное помещение', 'Корпус 3', 'Сектор В',
                 '5', '9', '—', '—', '1', '14:00', 'Сидорова', 'Проверено'],
            ]},
        ], 'summary': 'Итого по разделу: 1 запись'},
    ],
    'summary': 'Всего: 7 записей',
}


def validate_report(value):
    """Reject oversized or malformed input before constructing table widgets."""
    if not isinstance(value, dict) or value.get('format') != FORMAT:
        raise ValueError('Неподдерживаемый формат таблицы')

    def short_text(text, label):
        if not isinstance(text, str) or len(text) > 500:
            raise ValueError(f'Недопустимое значение: {label}')
        return text

    short_text(value.get('title'), 'заголовок')
    short_text(value.get('subtitle', ''), 'подзаголовок')
    short_text(value.get('summary', ''), 'итог')
    sections = value.get('sections')
    if not isinstance(sections, list) or not 1 <= len(sections) <= 30:
        raise ValueError('Ожидается от 1 до 30 разделов')
    # Count the two header rows and every rendered band, including final totals.
    total_rows = 2 + bool(value.get('summary'))
    for section in sections:
        if not isinstance(section, dict):
            raise ValueError('Неверный раздел')
        short_text(section.get('title'), 'раздел')
        short_text(section.get('summary', ''), 'итог раздела')
        groups = section.get('groups')
        if not isinstance(groups, list) or not 1 <= len(groups) <= 100:
            raise ValueError('Раздел должен содержать группы')
        total_rows += 1 + bool(section.get('summary'))
        for group in groups:
            if not isinstance(group, dict):
                raise ValueError('Неверная группа')
            short_text(group.get('title'), 'группа')
            rows = group.get('rows')
            if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
                raise ValueError('Группа должна содержать строки')
            total_rows += 1 + len(rows)
            if total_rows > MAX_WIDGET_ROWS:
                raise ValueError('Слишком много строк (предел 400)')
            for cells in rows:
                if not isinstance(cells, list) or len(cells) != len(COLUMNS):
                    raise ValueError(f'В строке должно быть {len(COLUMNS)} ячеек')
                for cell in cells:
                    short_text(cell, 'ячейка')
    return value


package store

import "time"

// Day returns the day number of t (UTC).
func Day(t time.Time) int { return int(t.Unix() / 86400) }

// Week returns the number of the ISO-style week (Monday to Sunday) that contains a day.
func Week(day int) int { return (day + 3) / 7 }

// WeekStart returns the day number of the Monday that starts week w.
func WeekStart(w int) int { return w*7 - 3 }

// DayString renders a day number as YYYY-MM-DD.
func DayString(day int) string { return time.Unix(int64(day)*86400, 0).UTC().Format("2006-01-02") }

// ParseDayString parses YYYY-MM-DD into a day number.
func ParseDayString(s string) (int, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return 0, err
	}
	return Day(t), nil
}

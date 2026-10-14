extends RefCounted

const MAX_ITEMS := 16


static func clamp_score(value: int, lo: int, hi: int) -> int:
	if value < lo:
		return lo
	if value > hi:
		return hi
	return value


func format_score(value: int) -> String:
	return "%06d" % clamp_score(value, 0, 999999)

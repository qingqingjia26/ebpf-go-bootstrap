package convert

func Int8Slice2String(slice []int8) string {
	buf := make([]byte, len(slice))
	for i, v := range slice {
		buf[i] = byte(v)
	}
	return string(buf)
}

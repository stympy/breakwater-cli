package bundle

// SetMaxDescriptors lowers the Validate walk budget for a test and returns
// a func that restores it.
func SetMaxDescriptors(n int) (restore func()) {
	old := maxDescriptors
	maxDescriptors = n
	return func() { maxDescriptors = old }
}

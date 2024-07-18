package notify

func ShowNotification(message string) func() {
	return showNotification(message)
}

from src.outbox.consumer import consumer

if __name__ == '__main__':
    print('Starting outbox consumer (press Ctrl-C to stop)')
    try:
        consumer.start()
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        consumer.stop()
        print('Stopped')

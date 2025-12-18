from apscheduler.schedulers.background import BackgroundScheduler

def job():
    print("Scheduled task running...")

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(job, "interval", hours=24)
    scheduler.start()

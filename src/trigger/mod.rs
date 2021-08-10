use std::time::Duration;

pub trait Trigger {
    fn provide_events(&self, handle: &calloop::LoopHandle<calloop::LoopSignal>) -> anyhow::Result<()>;
}

pub struct TimerTrigger {
    interval: Duration,
}

impl TimerTrigger {
    pub fn new(interval: Duration) -> Self {
        Self { interval }
    }
}


impl Trigger for TimerTrigger {
    fn provide_events(&self, handle: &calloop::LoopHandle<calloop::LoopSignal>) -> anyhow::Result<()> {
        let interval = self.interval.clone();

        let source = calloop::timer::Timer::new()?;
        let timer_handle = source.handle();
        timer_handle.add_timeout(interval, "Timeout reached!");
    
        handle.insert_source(
            source,
            move |event, th, _loop_signal| {
                println!("Event fired: {}", event);
                th.add_timeout(interval, "Timeout reached again!");
                // loop_signal.stop();
            }
        )?;

        Ok(())
    }
}

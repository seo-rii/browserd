use std::sync::{Arc, Barrier};
use std::thread;

use browserd_features::{
    AdmissionClass, AdmissionError, FeatureAdmission, FeatureConcurrencyLimits,
};

#[test]
fn independent_resource_classes_do_not_consume_each_others_slots() {
    let admission = FeatureAdmission::new(FeatureConcurrencyLimits {
        pdf: 1,
        full_page_screenshot: 1,
        large_snapshot: 2,
        scrape: 1,
    });
    let pdf = admission.acquire(AdmissionClass::Pdf);
    assert!(pdf.is_ok());
    assert_eq!(
        admission.acquire(AdmissionClass::Pdf),
        Err(AdmissionError::AtCapacity)
    );
    assert!(
        admission
            .acquire(AdmissionClass::FullPageScreenshot)
            .is_ok()
    );
}

#[test]
fn admission_is_linearizable_and_drop_releases_exactly_once() {
    let admission = Arc::new(FeatureAdmission::new(FeatureConcurrencyLimits {
        pdf: 1,
        full_page_screenshot: 1,
        large_snapshot: 1,
        scrape: 1,
    }));
    let barrier = Arc::new(Barrier::new(17));
    let hold = Arc::new(Barrier::new(17));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let admission = admission.clone();
        let barrier = barrier.clone();
        let hold = hold.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            let permit = admission.acquire(AdmissionClass::LargeSnapshot);
            hold.wait();
            permit
        }));
    }
    barrier.wait();
    hold.wait();

    let mut permits = Vec::new();
    let mut winners = 0;
    for handle in threads {
        let result = match handle.join() {
            Ok(result) => result,
            Err(_) => return,
        };
        if let Ok(permit) = result {
            winners += 1;
            permits.push(permit);
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(admission.in_use(AdmissionClass::LargeSnapshot), 1);
    drop(permits);
    assert_eq!(admission.in_use(AdmissionClass::LargeSnapshot), 0);
    assert!(admission.acquire(AdmissionClass::LargeSnapshot).is_ok());
}

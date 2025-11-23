// Test the randomizer to verify rand_agents integration
use blanktrace::config::FingerprintConfig;
use blanktrace::randomizer::Randomizer;

fn main() {
    let config = FingerprintConfig {
        rotation_mode: "launch".to_string(),
        rotation_interval: 3600,
        randomize_user_agent: true,
        randomize_accept_language: true,
        strip_referer: false,
        accept_languages: vec!["en-US".to_string(), "de-DE".to_string()],
    };

    let mut randomizer = Randomizer::new(&config);

    println!("Initial User-Agent: {}", randomizer.current_ua);
    println!("Initial Accept-Language: {}", randomizer.current_lang);
    println!();

    // Generate 5 random user agents
    println!("Rotating user agents:");
    for i in 1..=5 {
        let ua = randomizer.rotate_user_agent();
        println!("  {}. {}", i, ua);
    }

    println!();
    println!("Rotating accept languages:");
    for i in 1..=5 {
        let lang = randomizer.rotate_accept_language();
        println!("  {}. {}", i, lang);
    }
}

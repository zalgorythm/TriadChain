#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_genesis_creation() {
        let genesis = Triad::new(0, "0".to_string(), None);
        let triad = genesis.read();
        assert!(triad.is_root());
    }
}

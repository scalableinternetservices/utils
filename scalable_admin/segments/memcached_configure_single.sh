# Configure rails to use dalli
sed -i 's/# config.cache_store = :mem_cache_store/config.cache_store = :dalli_store/' config/environments/production.rb

#pragma once

#include <list>
#include <unordered_map>

template <typename Key, typename Value>
class LRUCache {
public:
    using Entry = std::pair<Key, Value>;

    LRUCache(size_t capacity)
        : capacity_(capacity)
    {
        listEntryMap_.reserve(capacity_);
    }

    bool inCache(const Key& key) { return listEntryMap_.count(key) > 0; }

    Value* get(const Key& key)
    {
        const auto it = listEntryMap_.find(key);
        if (it == listEntryMap_.end()) {
            return nullptr;
        }
        // Move to front of LRU
        lru_.splice(lru_.begin(), lru_, it->second);
        return &it->second->second;
    }

    // Returns true if element was inserted
    bool set(const Key& key, Value value)
    {
        auto it = listEntryMap_.find(key);
        if (it != listEntryMap_.end()) {
            it->second->second = std::move(value);
            lru_.splice(lru_.begin(), lru_, it->second);
            return false;
        }

        if (size() >= capacity()) {
            // Evict least recently used element
            listEntryMap_.erase(leastRecentlyUsed().first);
            lru_.pop_back();
        }

        // Insert the new element at the front of the LRU list and add it to the cache.
        lru_.emplace_front(key, std::move(value));
        listEntryMap_[key] = lru_.begin();
        return true;
    }

    size_t size() const { return listEntryMap_.size(); }
    size_t capacity() const { return capacity_; }

    const Entry& lastRecentlyUsed() const { return lru_.front(); }
    const Entry& leastRecentlyUsed() const { return lru_.back(); }

    // Use these to iterate in last recently used order
    auto begin() { return lru_.begin(); }
    auto end() { return lru_.end(); }

    // Use these to iterate in least recently used order
    auto rbegin() { return lru_.rbegin(); }
    auto rend() { return lru_.rend(); }

private:
    // TODO: Custom allocator for list so they are all contiguous in memory?
    std::list<Entry> lru_;
    std::unordered_map<Key, typename std::list<Entry>::iterator> listEntryMap_;
    size_t capacity_;
};

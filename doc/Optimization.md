## Performance Optimization

### API Performance Issues

If you experience slow response times or endless loops:

1. **Check System Resources**
   ```bash
   # Monitor CPU and memory usage
   htop
   
   # Check GPU memory (if using GPU)
   nvidia-smi
   ```

2. **Run Performance Tests**
   ```bash
   # Test API performance
   python scripts/monitor_performance.py
   ```

3. **Optimize Configuration**
   ```bash
   # Reduce batch sizes for memory-constrained systems
   export EMBEDDING_BATCH_SIZE=32
   export MAX_CONTEXT_LENGTH=4096
   
   # Use CPU-only mode if GPU memory is insufficient
   export DEVICE=cpu
   ```

4. **Common Performance Issues**
   - **Endless loops**: Usually caused by LLM generation timeouts. Check your Ollama/Hugging Face connection.
   - **Slow searches**: Vector database may need optimization. Consider rebuilding with smaller chunks.
   - **Memory issues**: Reduce `MAX_SEARCH_RESULTS` and `MAX_CONTEXT_LENGTH` in config.

5. **Timeout Settings**
   - Embedding generation: 5 seconds
   - Vector search: 10 seconds  
   - LLM generation: 30 seconds
   - Query routing: 5 seconds

### Performance Monitoring

The system includes built-in performance monitoring:

```bash
# Monitor real-time performance
python scripts/monitor_performance.py

# Check API health
curl http://localhost:8000/api/v1/health

# Test specific endpoints
curl -X POST http://localhost:8000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "CVE-2021-44228", "top_k": 5}'
```

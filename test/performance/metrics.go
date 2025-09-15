/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//go:build performance
// +build performance

package performance

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// NewPerformanceMetrics creates a new performance metrics instance
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		ReconcileTimes: make([]time.Duration, 0),
		MemoryUsage:    make([]int64, 0),
		CPUUsage:       make([]float64, 0),
	}
}

// RecordReconcileTime records a reconciliation time
func (m *PerformanceMetrics) RecordReconcileTime(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.ReconcileTimes = append(m.ReconcileTimes, duration)
}

// RecordReconcileSuccess records a successful reconciliation
func (m *PerformanceMetrics) RecordReconcileSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.ReconcileSuccesses++
}

// RecordReconcileError records a failed reconciliation
func (m *PerformanceMetrics) RecordReconcileError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.ReconcileErrors++
}

// RecordMemoryUsage records memory usage in MB
func (m *PerformanceMetrics) RecordMemoryUsage(memoryMB int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.MemoryUsage = append(m.MemoryUsage, memoryMB)
}

// RecordCPUUsage records CPU usage as percentage
func (m *PerformanceMetrics) RecordCPUUsage(cpuPercent float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.CPUUsage = append(m.CPUUsage, cpuPercent)
}

// CalculateStatistics calculates performance statistics
func (m *PerformanceMetrics) CalculateStatistics() *PerformanceStatistics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	stats := &PerformanceStatistics{}
	
	if len(m.ReconcileTimes) > 0 {
		// Calculate reconciliation time statistics
		times := make([]time.Duration, len(m.ReconcileTimes))
		copy(times, m.ReconcileTimes)
		sort.Slice(times, func(i, j int) bool {
			return times[i] < times[j]
		})
		
		stats.ReconcileTimeStats = TimeStatistics{
			Count:  len(times),
			Min:    times[0],
			Max:    times[len(times)-1],
			Mean:   m.calculateMeanDuration(times),
			Median: m.calculatePercentileDuration(times, 50),
			P95:    m.calculatePercentileDuration(times, 95),
			P99:    m.calculatePercentileDuration(times, 99),
			StdDev: m.calculateStdDevDuration(times),
		}
		
		m.P50ReconcileTime = stats.ReconcileTimeStats.Median
		m.P95ReconcileTime = stats.ReconcileTimeStats.P95
		m.P99ReconcileTime = stats.ReconcileTimeStats.P99
	}
	
	// Calculate error rate
	totalOperations := m.ReconcileSuccesses + m.ReconcileErrors
	if totalOperations > 0 {
		m.ErrorRate = float64(m.ReconcileErrors) / float64(totalOperations)
		stats.ErrorRate = m.ErrorRate
	}
	
	// Calculate throughput
	if len(m.ReconcileTimes) > 1 {
		totalDuration := m.ReconcileTimes[len(m.ReconcileTimes)-1] - m.ReconcileTimes[0]
		if totalDuration > 0 {
			m.ReconciliationsPerSecond = float64(len(m.ReconcileTimes)) / totalDuration.Seconds()
			stats.ThroughputRPS = m.ReconciliationsPerSecond
		}
	}
	
	// Calculate memory statistics
	if len(m.MemoryUsage) > 0 {
		memory := make([]int64, len(m.MemoryUsage))
		copy(memory, m.MemoryUsage)
		sort.Slice(memory, func(i, j int) bool {
			return memory[i] < memory[j]
		})
		
		stats.MemoryStats = ResourceStatistics{
			Count:  len(memory),
			Min:    float64(memory[0]),
			Max:    float64(memory[len(memory)-1]),
			Mean:   m.calculateMeanInt64(memory),
			Median: float64(m.calculatePercentileInt64(memory, 50)),
			P95:    float64(m.calculatePercentileInt64(memory, 95)),
			P99:    float64(m.calculatePercentileInt64(memory, 99)),
			StdDev: m.calculateStdDevInt64(memory),
		}
	}
	
	// Calculate CPU statistics
	if len(m.CPUUsage) > 0 {
		cpu := make([]float64, len(m.CPUUsage))
		copy(cpu, m.CPUUsage)
		sort.Float64s(cpu)
		
		stats.CPUStats = ResourceStatistics{
			Count:  len(cpu),
			Min:    cpu[0],
			Max:    cpu[len(cpu)-1],
			Mean:   m.calculateMeanFloat64(cpu),
			Median: m.calculatePercentileFloat64(cpu, 50),
			P95:    m.calculatePercentileFloat64(cpu, 95),
			P99:    m.calculatePercentileFloat64(cpu, 99),
			StdDev: m.calculateStdDevFloat64(cpu),
		}
	}
	
	return stats
}

// PerformanceStatistics holds calculated performance statistics
type PerformanceStatistics struct {
	ReconcileTimeStats TimeStatistics      `json:"reconcile_time_stats"`
	MemoryStats        ResourceStatistics  `json:"memory_stats"`
	CPUStats           ResourceStatistics  `json:"cpu_stats"`
	ErrorRate          float64             `json:"error_rate"`
	ThroughputRPS      float64             `json:"throughput_rps"`
}

// TimeStatistics holds time-based statistics
type TimeStatistics struct {
	Count  int           `json:"count"`
	Min    time.Duration `json:"min"`
	Max    time.Duration `json:"max"`
	Mean   time.Duration `json:"mean"`
	Median time.Duration `json:"median"`
	P95    time.Duration `json:"p95"`
	P99    time.Duration `json:"p99"`
	StdDev time.Duration `json:"std_dev"`
}

// ResourceStatistics holds resource usage statistics
type ResourceStatistics struct {
	Count  int     `json:"count"`
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
	StdDev float64 `json:"std_dev"`
}

// Helper methods for the test suite

// calculateAverage calculates average duration
func (suite *PerformanceTestSuite) calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

// calculatePercentile calculates percentile duration
func (suite *PerformanceTestSuite) calculatePercentile(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	
	index := int(float64(len(sorted)-1) * percentile / 100.0)
	return sorted[index]
}

// calculateMin calculates minimum duration
func (suite *PerformanceTestSuite) calculateMin(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	min := durations[0]
	for _, d := range durations[1:] {
		if d < min {
			min = d
		}
	}
	
	return min
}

// calculateMax calculates maximum duration
func (suite *PerformanceTestSuite) calculateMax(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	max := durations[0]
	for _, d := range durations[1:] {
		if d > max {
			max = d
		}
	}
	
	return max
}

// calculateFinalMetrics calculates final metrics after load test
func (suite *PerformanceTestSuite) calculateFinalMetrics() {
	stats := suite.metrics.CalculateStatistics()
	
	suite.metrics.P50ReconcileTime = stats.ReconcileTimeStats.Median
	suite.metrics.P95ReconcileTime = stats.ReconcileTimeStats.P95
	suite.metrics.P99ReconcileTime = stats.ReconcileTimeStats.P99
	suite.metrics.ErrorRate = stats.ErrorRate
	suite.metrics.ReconciliationsPerSecond = stats.ThroughputRPS
}

// printFinalMetrics prints final performance metrics
func (suite *PerformanceTestSuite) printFinalMetrics() {
	stats := suite.metrics.CalculateStatistics()
	
	suite.T().Log("=== Performance Test Results ===")
	
	if stats.ReconcileTimeStats.Count > 0 {
		suite.T().Logf("Reconciliation Times:")
		suite.T().Logf("  Count: %d", stats.ReconcileTimeStats.Count)
		suite.T().Logf("  Min: %v", stats.ReconcileTimeStats.Min)
		suite.T().Logf("  Max: %v", stats.ReconcileTimeStats.Max)
		suite.T().Logf("  Mean: %v", stats.ReconcileTimeStats.Mean)
		suite.T().Logf("  Median: %v", stats.ReconcileTimeStats.Median)
		suite.T().Logf("  P95: %v", stats.ReconcileTimeStats.P95)
		suite.T().Logf("  P99: %v", stats.ReconcileTimeStats.P99)
		suite.T().Logf("  StdDev: %v", stats.ReconcileTimeStats.StdDev)
	}
	
	suite.T().Logf("Throughput: %.2f reconciliations/sec", stats.ThroughputRPS)
	suite.T().Logf("Error Rate: %.2f%%", stats.ErrorRate*100)
	
	if stats.MemoryStats.Count > 0 {
		suite.T().Logf("Memory Usage (MB):")
		suite.T().Logf("  Min: %.2f", stats.MemoryStats.Min)
		suite.T().Logf("  Max: %.2f", stats.MemoryStats.Max)
		suite.T().Logf("  Mean: %.2f", stats.MemoryStats.Mean)
		suite.T().Logf("  P95: %.2f", stats.MemoryStats.P95)
	}
	
	if stats.CPUStats.Count > 0 {
		suite.T().Logf("CPU Usage (%%):")
		suite.T().Logf("  Min: %.2f", stats.CPUStats.Min)
		suite.T().Logf("  Max: %.2f", stats.CPUStats.Max)
		suite.T().Logf("  Mean: %.2f", stats.CPUStats.Mean)
		suite.T().Logf("  P95: %.2f", stats.CPUStats.P95)
	}
	
	// Export metrics to JSON for further analysis
	if jsonData, err := json.MarshalIndent(stats, "", "  "); err == nil {
		suite.T().Logf("JSON Metrics: %s", string(jsonData))
	}
}

// Helper methods for metrics calculations

// calculateMeanDuration calculates mean of durations
func (m *PerformanceMetrics) calculateMeanDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

// calculatePercentileDuration calculates percentile of durations
func (m *PerformanceMetrics) calculatePercentileDuration(durations []time.Duration, percentile float64) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	index := int(float64(len(durations)-1) * percentile / 100.0)
	return durations[index]
}

// calculateStdDevDuration calculates standard deviation of durations
func (m *PerformanceMetrics) calculateStdDevDuration(durations []time.Duration) time.Duration {
	if len(durations) <= 1 {
		return 0
	}
	
	mean := m.calculateMeanDuration(durations)
	var sumSquares float64
	
	for _, d := range durations {
		diff := float64(d - mean)
		sumSquares += diff * diff
	}
	
	variance := sumSquares / float64(len(durations)-1)
	return time.Duration(math.Sqrt(variance))
}

// calculateMeanInt64 calculates mean of int64 values
func (m *PerformanceMetrics) calculateMeanInt64(values []int64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	var total int64
	for _, v := range values {
		total += v
	}
	
	return float64(total) / float64(len(values))
}

// calculatePercentileInt64 calculates percentile of int64 values
func (m *PerformanceMetrics) calculatePercentileInt64(values []int64, percentile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	
	index := int(float64(len(values)-1) * percentile / 100.0)
	return values[index]
}

// calculateStdDevInt64 calculates standard deviation of int64 values
func (m *PerformanceMetrics) calculateStdDevInt64(values []int64) float64 {
	if len(values) <= 1 {
		return 0
	}
	
	mean := m.calculateMeanInt64(values)
	var sumSquares float64
	
	for _, v := range values {
		diff := float64(v) - mean
		sumSquares += diff * diff
	}
	
	variance := sumSquares / float64(len(values)-1)
	return math.Sqrt(variance)
}

// calculateMeanFloat64 calculates mean of float64 values
func (m *PerformanceMetrics) calculateMeanFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	var total float64
	for _, v := range values {
		total += v
	}
	
	return total / float64(len(values))
}

// calculatePercentileFloat64 calculates percentile of float64 values
func (m *PerformanceMetrics) calculatePercentileFloat64(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	index := int(float64(len(values)-1) * percentile / 100.0)
	return values[index]
}

// calculateStdDevFloat64 calculates standard deviation of float64 values
func (m *PerformanceMetrics) calculateStdDevFloat64(values []float64) float64 {
	if len(values) <= 1 {
		return 0
	}
	
	mean := m.calculateMeanFloat64(values)
	var sumSquares float64
	
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	
	variance := sumSquares / float64(len(values)-1)
	return math.Sqrt(variance)
}

// ExportMetrics exports metrics to a file
func (m *PerformanceMetrics) ExportMetrics(filename string) error {
	stats := m.CalculateStatistics()
	
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}
	
	// In a real implementation, you would write to a file
	// For now, we'll just return the data as a string
	fmt.Printf("Metrics exported to %s:\n%s\n", filename, string(data))
	
	return nil
}

// CompareMetrics compares current metrics with baseline
func (m *PerformanceMetrics) CompareMetrics(baseline *PerformanceStatistics) *MetricsComparison {
	current := m.CalculateStatistics()
	
	return &MetricsComparison{
		Current:  current,
		Baseline: baseline,
		Improvements: MetricsChanges{
			ReconcileTimeImprovement: calculateImprovement(
				baseline.ReconcileTimeStats.Mean.Seconds(),
				current.ReconcileTimeStats.Mean.Seconds(),
			),
			ThroughputImprovement: calculateImprovement(
				baseline.ThroughputRPS,
				current.ThroughputRPS,
			),
			ErrorRateImprovement: calculateImprovement(
				baseline.ErrorRate,
				current.ErrorRate,
			),
		},
	}
}

// MetricsComparison holds comparison between current and baseline metrics
type MetricsComparison struct {
	Current      *PerformanceStatistics `json:"current"`
	Baseline     *PerformanceStatistics `json:"baseline"`
	Improvements MetricsChanges         `json:"improvements"`
}

// MetricsChanges holds percentage changes in metrics
type MetricsChanges struct {
	ReconcileTimeImprovement float64 `json:"reconcile_time_improvement"`
	ThroughputImprovement    float64 `json:"throughput_improvement"`
	ErrorRateImprovement     float64 `json:"error_rate_improvement"`
}

// calculateImprovement calculates percentage improvement (negative means regression)
func calculateImprovement(baseline, current float64) float64 {
	if baseline == 0 {
		return 0
	}
	
	return ((baseline - current) / baseline) * 100
}
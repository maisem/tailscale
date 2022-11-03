// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Profile is a common stacktrace profile format.
//
// Measurements represented with this format should follow the
// following conventions:
//
// - Consumers should treat unset optional fields as if they had been
//   set with their default value.
//
// - When possible, measurements should be stored in "unsampled" form
//   that is most useful to humans.  There should be enough
//   information present to determine the original sampled values.
//
// - On-disk, the serialized proto must be gzip-compressed.
//
// - The profile is represented as a set of samples, where each sample
//   references a sequence of locations, and where each location belongs
//   to a mapping.
// - There is a N->1 relationship from sample.location_id entries to
//   locations. For every sample.location_id entry there must be a
//   unique Location with that id.
// - There is an optional N->1 relationship from locations to
//   mappings. For every nonzero Location.mapping_id there must be a
//   unique Mapping with that id.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.6
// source: profile.proto

package profilepb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Profile struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// A description of the samples associated with each Sample.value.
	// For a cpu profile this might be:
	//
	//	[["cpu","nanoseconds"]] or [["wall","seconds"]] or [["syscall","count"]]
	//
	// For a heap profile, this might be:
	//
	//	[["allocations","count"], ["space","bytes"]],
	//
	// If one of the values represents the number of events represented
	// by the sample, by convention it should be at index 0 and use
	// sample_type.unit == "count".
	SampleType []*ValueType `protobuf:"bytes,1,rep,name=sample_type,json=sampleType,proto3" json:"sample_type,omitempty"`
	// The set of samples recorded in this profile.
	Sample []*Sample `protobuf:"bytes,2,rep,name=sample,proto3" json:"sample,omitempty"`
	// Mapping from address ranges to the image/binary/library mapped
	// into that address range.  mapping[0] will be the main binary.
	Mapping []*Mapping `protobuf:"bytes,3,rep,name=mapping,proto3" json:"mapping,omitempty"`
	// Useful program location
	Location []*Location `protobuf:"bytes,4,rep,name=location,proto3" json:"location,omitempty"`
	// Functions referenced by locations
	Function []*Function `protobuf:"bytes,5,rep,name=function,proto3" json:"function,omitempty"`
	// A common table for strings referenced by various messages.
	// string_table[0] must always be "".
	StringTable []string `protobuf:"bytes,6,rep,name=string_table,json=stringTable,proto3" json:"string_table,omitempty"`
	// frames with Function.function_name fully matching the following
	// regexp will be dropped from the samples, along with their successors.
	DropFrames int64 `protobuf:"varint,7,opt,name=drop_frames,json=dropFrames,proto3" json:"drop_frames,omitempty"` // Index into string table.
	// frames with Function.function_name fully matching the following
	// regexp will be kept, even if it matches drop_frames.
	KeepFrames int64 `protobuf:"varint,8,opt,name=keep_frames,json=keepFrames,proto3" json:"keep_frames,omitempty"` // Index into string table.
	// Time of collection (UTC) represented as nanoseconds past the epoch.
	TimeNanos int64 `protobuf:"varint,9,opt,name=time_nanos,json=timeNanos,proto3" json:"time_nanos,omitempty"`
	// Duration of the profile, if a duration makes sense.
	DurationNanos int64 `protobuf:"varint,10,opt,name=duration_nanos,json=durationNanos,proto3" json:"duration_nanos,omitempty"`
	// The kind of events between sampled ocurrences.
	// e.g [ "cpu","cycles" ] or [ "heap","bytes" ]
	PeriodType *ValueType `protobuf:"bytes,11,opt,name=period_type,json=periodType,proto3" json:"period_type,omitempty"`
	// The number of events between sampled occurrences.
	Period int64 `protobuf:"varint,12,opt,name=period,proto3" json:"period,omitempty"`
	// Freeform text associated to the profile.
	Comment []int64 `protobuf:"varint,13,rep,packed,name=comment,proto3" json:"comment,omitempty"` // Indices into string table.
	// Index into the string table of the type of the preferred sample
	// value. If unset, clients should default to the last sample value.
	DefaultSampleType int64 `protobuf:"varint,14,opt,name=default_sample_type,json=defaultSampleType,proto3" json:"default_sample_type,omitempty"`
}

func (x *Profile) Reset() {
	*x = Profile{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Profile) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Profile) ProtoMessage() {}

func (x *Profile) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Profile.ProtoReflect.Descriptor instead.
func (*Profile) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{0}
}

func (x *Profile) GetSampleType() []*ValueType {
	if x != nil {
		return x.SampleType
	}
	return nil
}

func (x *Profile) GetSample() []*Sample {
	if x != nil {
		return x.Sample
	}
	return nil
}

func (x *Profile) GetMapping() []*Mapping {
	if x != nil {
		return x.Mapping
	}
	return nil
}

func (x *Profile) GetLocation() []*Location {
	if x != nil {
		return x.Location
	}
	return nil
}

func (x *Profile) GetFunction() []*Function {
	if x != nil {
		return x.Function
	}
	return nil
}

func (x *Profile) GetStringTable() []string {
	if x != nil {
		return x.StringTable
	}
	return nil
}

func (x *Profile) GetDropFrames() int64 {
	if x != nil {
		return x.DropFrames
	}
	return 0
}

func (x *Profile) GetKeepFrames() int64 {
	if x != nil {
		return x.KeepFrames
	}
	return 0
}

func (x *Profile) GetTimeNanos() int64 {
	if x != nil {
		return x.TimeNanos
	}
	return 0
}

func (x *Profile) GetDurationNanos() int64 {
	if x != nil {
		return x.DurationNanos
	}
	return 0
}

func (x *Profile) GetPeriodType() *ValueType {
	if x != nil {
		return x.PeriodType
	}
	return nil
}

func (x *Profile) GetPeriod() int64 {
	if x != nil {
		return x.Period
	}
	return 0
}

func (x *Profile) GetComment() []int64 {
	if x != nil {
		return x.Comment
	}
	return nil
}

func (x *Profile) GetDefaultSampleType() int64 {
	if x != nil {
		return x.DefaultSampleType
	}
	return 0
}

// ValueType describes the semantics and measurement units of a value.
type ValueType struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type int64 `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"` // Index into string table.
	Unit int64 `protobuf:"varint,2,opt,name=unit,proto3" json:"unit,omitempty"` // Index into string table.
}

func (x *ValueType) Reset() {
	*x = ValueType{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ValueType) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ValueType) ProtoMessage() {}

func (x *ValueType) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ValueType.ProtoReflect.Descriptor instead.
func (*ValueType) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{1}
}

func (x *ValueType) GetType() int64 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *ValueType) GetUnit() int64 {
	if x != nil {
		return x.Unit
	}
	return 0
}

// Each Sample records values encountered in some program
// context. The program context is typically a stack trace, perhaps
// augmented with auxiliary information like the thread-id, some
// indicator of a higher level request being handled etc.
type Sample struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ids recorded here correspond to a Profile.location.id.
	// The leaf is at location_id[0].
	LocationId []uint64 `protobuf:"varint,1,rep,packed,name=location_id,json=locationId,proto3" json:"location_id,omitempty"`
	// The type and unit of each value is defined by the corresponding
	// entry in Profile.sample_type. All samples must have the same
	// number of values, the same as the length of Profile.sample_type.
	// When aggregating multiple samples into a single sample, the
	// result has a list of values that is the element-wise sum of the
	// lists of the originals.
	Value []int64 `protobuf:"varint,2,rep,packed,name=value,proto3" json:"value,omitempty"`
	// label includes additional context for this sample. It can include
	// things like a thread id, allocation size, etc
	Label []*Label `protobuf:"bytes,3,rep,name=label,proto3" json:"label,omitempty"`
}

func (x *Sample) Reset() {
	*x = Sample{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Sample) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Sample) ProtoMessage() {}

func (x *Sample) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Sample.ProtoReflect.Descriptor instead.
func (*Sample) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{2}
}

func (x *Sample) GetLocationId() []uint64 {
	if x != nil {
		return x.LocationId
	}
	return nil
}

func (x *Sample) GetValue() []int64 {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *Sample) GetLabel() []*Label {
	if x != nil {
		return x.Label
	}
	return nil
}

type Label struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Key int64 `protobuf:"varint,1,opt,name=key,proto3" json:"key,omitempty"` // Index into string table
	// At most one of the following must be present
	Str int64 `protobuf:"varint,2,opt,name=str,proto3" json:"str,omitempty"` // Index into string table
	Num int64 `protobuf:"varint,3,opt,name=num,proto3" json:"num,omitempty"`
	// Should only be present when num is present.
	// Specifies the units of num.
	// Use arbitrary string (for example, "requests") as a custom count unit.
	// If no unit is specified, consumer may apply heuristic to deduce the unit.
	// Consumers may also  interpret units like "bytes" and "kilobytes" as memory
	// units and units like "seconds" and "nanoseconds" as time units,
	// and apply appropriate unit conversions to these.
	NumUnit int64 `protobuf:"varint,4,opt,name=num_unit,json=numUnit,proto3" json:"num_unit,omitempty"` // Index into string table
}

func (x *Label) Reset() {
	*x = Label{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Label) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Label) ProtoMessage() {}

func (x *Label) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Label.ProtoReflect.Descriptor instead.
func (*Label) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{3}
}

func (x *Label) GetKey() int64 {
	if x != nil {
		return x.Key
	}
	return 0
}

func (x *Label) GetStr() int64 {
	if x != nil {
		return x.Str
	}
	return 0
}

func (x *Label) GetNum() int64 {
	if x != nil {
		return x.Num
	}
	return 0
}

func (x *Label) GetNumUnit() int64 {
	if x != nil {
		return x.NumUnit
	}
	return 0
}

type Mapping struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique nonzero id for the mapping.
	Id uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// Address at which the binary (or DLL) is loaded into memory.
	MemoryStart uint64 `protobuf:"varint,2,opt,name=memory_start,json=memoryStart,proto3" json:"memory_start,omitempty"`
	// The limit of the address range occupied by this mapping.
	MemoryLimit uint64 `protobuf:"varint,3,opt,name=memory_limit,json=memoryLimit,proto3" json:"memory_limit,omitempty"`
	// Offset in the binary that corresponds to the first mapped address.
	FileOffset uint64 `protobuf:"varint,4,opt,name=file_offset,json=fileOffset,proto3" json:"file_offset,omitempty"`
	// The object this entry is loaded from.  This can be a filename on
	// disk for the main binary and shared libraries, or virtual
	// abstractions like "[vdso]".
	Filename int64 `protobuf:"varint,5,opt,name=filename,proto3" json:"filename,omitempty"` // Index into string table
	// A string that uniquely identifies a particular program version
	// with high probability. E.g., for binaries generated by GNU tools,
	// it could be the contents of the .note.gnu.build-id field.
	BuildId int64 `protobuf:"varint,6,opt,name=build_id,json=buildId,proto3" json:"build_id,omitempty"` // Index into string table
	// The following fields indicate the resolution of symbolic info.
	HasFunctions    bool `protobuf:"varint,7,opt,name=has_functions,json=hasFunctions,proto3" json:"has_functions,omitempty"`
	HasFilenames    bool `protobuf:"varint,8,opt,name=has_filenames,json=hasFilenames,proto3" json:"has_filenames,omitempty"`
	HasLineNumbers  bool `protobuf:"varint,9,opt,name=has_line_numbers,json=hasLineNumbers,proto3" json:"has_line_numbers,omitempty"`
	HasInlineFrames bool `protobuf:"varint,10,opt,name=has_inline_frames,json=hasInlineFrames,proto3" json:"has_inline_frames,omitempty"`
}

func (x *Mapping) Reset() {
	*x = Mapping{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Mapping) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Mapping) ProtoMessage() {}

func (x *Mapping) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Mapping.ProtoReflect.Descriptor instead.
func (*Mapping) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{4}
}

func (x *Mapping) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Mapping) GetMemoryStart() uint64 {
	if x != nil {
		return x.MemoryStart
	}
	return 0
}

func (x *Mapping) GetMemoryLimit() uint64 {
	if x != nil {
		return x.MemoryLimit
	}
	return 0
}

func (x *Mapping) GetFileOffset() uint64 {
	if x != nil {
		return x.FileOffset
	}
	return 0
}

func (x *Mapping) GetFilename() int64 {
	if x != nil {
		return x.Filename
	}
	return 0
}

func (x *Mapping) GetBuildId() int64 {
	if x != nil {
		return x.BuildId
	}
	return 0
}

func (x *Mapping) GetHasFunctions() bool {
	if x != nil {
		return x.HasFunctions
	}
	return false
}

func (x *Mapping) GetHasFilenames() bool {
	if x != nil {
		return x.HasFilenames
	}
	return false
}

func (x *Mapping) GetHasLineNumbers() bool {
	if x != nil {
		return x.HasLineNumbers
	}
	return false
}

func (x *Mapping) GetHasInlineFrames() bool {
	if x != nil {
		return x.HasInlineFrames
	}
	return false
}

// Describes function and line table debug information.
type Location struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique nonzero id for the location.  A profile could use
	// instruction addresses or any integer sequence as ids.
	Id uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// The id of the corresponding profile.Mapping for this location.
	// It can be unset if the mapping is unknown or not applicable for
	// this profile type.
	MappingId uint64 `protobuf:"varint,2,opt,name=mapping_id,json=mappingId,proto3" json:"mapping_id,omitempty"`
	// The instruction address for this location, if available.  It
	// should be within [Mapping.memory_start...Mapping.memory_limit]
	// for the corresponding mapping. A non-leaf address may be in the
	// middle of a call instruction. It is up to display tools to find
	// the beginning of the instruction if necessary.
	Address uint64 `protobuf:"varint,3,opt,name=address,proto3" json:"address,omitempty"`
	// Multiple line indicates this location has inlined functions,
	// where the last entry represents the caller into which the
	// preceding entries were inlined.
	//
	// E.g., if memcpy() is inlined into printf:
	//
	//	line[0].function_name == "memcpy"
	//	line[1].function_name == "printf"
	Line []*Line `protobuf:"bytes,4,rep,name=line,proto3" json:"line,omitempty"`
	// Provides an indication that multiple symbols map to this location's
	// address, for example due to identical code folding by the linker. In that
	// case the line information above represents one of the multiple
	// symbols. This field must be recomputed when the symbolization state of the
	// profile changes.
	IsFolded bool `protobuf:"varint,5,opt,name=is_folded,json=isFolded,proto3" json:"is_folded,omitempty"`
}

func (x *Location) Reset() {
	*x = Location{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Location) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Location) ProtoMessage() {}

func (x *Location) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Location.ProtoReflect.Descriptor instead.
func (*Location) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{5}
}

func (x *Location) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Location) GetMappingId() uint64 {
	if x != nil {
		return x.MappingId
	}
	return 0
}

func (x *Location) GetAddress() uint64 {
	if x != nil {
		return x.Address
	}
	return 0
}

func (x *Location) GetLine() []*Line {
	if x != nil {
		return x.Line
	}
	return nil
}

func (x *Location) GetIsFolded() bool {
	if x != nil {
		return x.IsFolded
	}
	return false
}

type Line struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The id of the corresponding profile.Function for this line.
	FunctionId uint64 `protobuf:"varint,1,opt,name=function_id,json=functionId,proto3" json:"function_id,omitempty"`
	// Line number in source code.
	Line int64 `protobuf:"varint,2,opt,name=line,proto3" json:"line,omitempty"`
}

func (x *Line) Reset() {
	*x = Line{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Line) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Line) ProtoMessage() {}

func (x *Line) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Line.ProtoReflect.Descriptor instead.
func (*Line) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{6}
}

func (x *Line) GetFunctionId() uint64 {
	if x != nil {
		return x.FunctionId
	}
	return 0
}

func (x *Line) GetLine() int64 {
	if x != nil {
		return x.Line
	}
	return 0
}

type Function struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Unique nonzero id for the function.
	Id uint64 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	// Name of the function, in human-readable form if available.
	Name int64 `protobuf:"varint,2,opt,name=name,proto3" json:"name,omitempty"` // Index into string table
	// Name of the function, as identified by the system.
	// For instance, it can be a C++ mangled name.
	SystemName int64 `protobuf:"varint,3,opt,name=system_name,json=systemName,proto3" json:"system_name,omitempty"` // Index into string table
	// Source file containing the function.
	Filename int64 `protobuf:"varint,4,opt,name=filename,proto3" json:"filename,omitempty"` // Index into string table
	// Line number in source file.
	StartLine int64 `protobuf:"varint,5,opt,name=start_line,json=startLine,proto3" json:"start_line,omitempty"`
}

func (x *Function) Reset() {
	*x = Function{}
	if protoimpl.UnsafeEnabled {
		mi := &file_profile_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Function) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Function) ProtoMessage() {}

func (x *Function) ProtoReflect() protoreflect.Message {
	mi := &file_profile_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Function.ProtoReflect.Descriptor instead.
func (*Function) Descriptor() ([]byte, []int) {
	return file_profile_proto_rawDescGZIP(), []int{7}
}

func (x *Function) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Function) GetName() int64 {
	if x != nil {
		return x.Name
	}
	return 0
}

func (x *Function) GetSystemName() int64 {
	if x != nil {
		return x.SystemName
	}
	return 0
}

func (x *Function) GetFilename() int64 {
	if x != nil {
		return x.Filename
	}
	return 0
}

func (x *Function) GetStartLine() int64 {
	if x != nil {
		return x.StartLine
	}
	return 0
}

var File_profile_proto protoreflect.FileDescriptor

var file_profile_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x12, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69,
	0x6c, 0x65, 0x73, 0x22, 0xf5, 0x04, 0x0a, 0x07, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x12,
	0x3e, 0x0a, 0x0b, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x52, 0x0a, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12,
	0x32, 0x0a, 0x06, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66,
	0x69, 0x6c, 0x65, 0x73, 0x2e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x52, 0x06, 0x73, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x12, 0x35, 0x0a, 0x07, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x18, 0x03,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e,
	0x67, 0x52, 0x07, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x38, 0x0a, 0x08, 0x6c, 0x6f,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x70,
	0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,
	0x73, 0x2e, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x6c, 0x6f, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x12, 0x38, 0x0a, 0x08, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f,
	0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e, 0x46, 0x75, 0x6e, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x21,
	0x0a, 0x0c, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x06,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x54, 0x61, 0x62, 0x6c,
	0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x64, 0x72, 0x6f, 0x70, 0x5f, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x64, 0x72, 0x6f, 0x70, 0x46, 0x72, 0x61, 0x6d,
	0x65, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6b, 0x65, 0x65, 0x70, 0x5f, 0x66, 0x72, 0x61, 0x6d, 0x65,
	0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x6b, 0x65, 0x65, 0x70, 0x46, 0x72, 0x61,
	0x6d, 0x65, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x69, 0x6d, 0x65, 0x5f, 0x6e, 0x61, 0x6e, 0x6f,
	0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x74, 0x69, 0x6d, 0x65, 0x4e, 0x61, 0x6e,
	0x6f, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6e,
	0x61, 0x6e, 0x6f, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x64, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x4e, 0x61, 0x6e, 0x6f, 0x73, 0x12, 0x3e, 0x0a, 0x0b, 0x70, 0x65, 0x72,
	0x69, 0x6f, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d,
	0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69,
	0x6c, 0x65, 0x73, 0x2e, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x0a, 0x70,
	0x65, 0x72, 0x69, 0x6f, 0x64, 0x54, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x65, 0x72,
	0x69, 0x6f, 0x64, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x70, 0x65, 0x72, 0x69, 0x6f,
	0x64, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x0d, 0x20, 0x03,
	0x28, 0x03, 0x52, 0x07, 0x63, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x13, 0x64,
	0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x03, 0x52, 0x11, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c,
	0x74, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x22, 0x33, 0x0a, 0x09, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04,
	0x75, 0x6e, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x75, 0x6e, 0x69, 0x74,
	0x22, 0x70, 0x0a, 0x06, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x6c, 0x6f,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x03, 0x28, 0x04, 0x52,
	0x0a, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x03, 0x28, 0x03, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x12, 0x2f, 0x0a, 0x05, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x52, 0x05, 0x6c, 0x61, 0x62,
	0x65, 0x6c, 0x22, 0x58, 0x0a, 0x05, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x10, 0x0a,
	0x03, 0x73, 0x74, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x73, 0x74, 0x72, 0x12,
	0x10, 0x0a, 0x03, 0x6e, 0x75, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x6e, 0x75,
	0x6d, 0x12, 0x19, 0x0a, 0x08, 0x6e, 0x75, 0x6d, 0x5f, 0x75, 0x6e, 0x69, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x07, 0x6e, 0x75, 0x6d, 0x55, 0x6e, 0x69, 0x74, 0x22, 0xd7, 0x02, 0x0a,
	0x07, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69, 0x64, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x65, 0x6d, 0x6f,
	0x72, 0x79, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b,
	0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x6d,
	0x65, 0x6d, 0x6f, 0x72, 0x79, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x0b, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x1f,
	0x0a, 0x0b, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x12,
	0x1a, 0x0a, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x62,
	0x75, 0x69, 0x6c, 0x64, 0x49, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x68, 0x61, 0x73, 0x5f, 0x66, 0x75,
	0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x68,
	0x61, 0x73, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x68,
	0x61, 0x73, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0c, 0x68, 0x61, 0x73, 0x46, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x12, 0x28, 0x0a, 0x10, 0x68, 0x61, 0x73, 0x5f, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x6e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x68, 0x61, 0x73, 0x4c,
	0x69, 0x6e, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x12, 0x2a, 0x0a, 0x11, 0x68, 0x61,
	0x73, 0x5f, 0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x66, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0f, 0x68, 0x61, 0x73, 0x49, 0x6e, 0x6c, 0x69, 0x6e, 0x65,
	0x46, 0x72, 0x61, 0x6d, 0x65, 0x73, 0x22, 0x9e, 0x01, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x69,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x09, 0x6d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67,
	0x49, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2c, 0x0a, 0x04,
	0x6c, 0x69, 0x6e, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x70, 0x65, 0x72,
	0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x2e,
	0x4c, 0x69, 0x6e, 0x65, 0x52, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x73,
	0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x69,
	0x73, 0x46, 0x6f, 0x6c, 0x64, 0x65, 0x64, 0x22, 0x3b, 0x0a, 0x04, 0x4c, 0x69, 0x6e, 0x65, 0x12,
	0x1f, 0x0a, 0x0b, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x66, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64,
	0x12, 0x12, 0x0a, 0x04, 0x6c, 0x69, 0x6e, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04,
	0x6c, 0x69, 0x6e, 0x65, 0x22, 0x8a, 0x01, 0x0a, 0x08, 0x46, 0x75, 0x6e, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x02, 0x69,
	0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x73, 0x79, 0x73, 0x74,
	0x65, 0x6d, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x6c, 0x69, 0x6e, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x09, 0x73, 0x74, 0x61, 0x72, 0x74, 0x4c, 0x69, 0x6e,
	0x65, 0x42, 0x2d, 0x0a, 0x1d, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x65, 0x72, 0x66, 0x74, 0x6f, 0x6f, 0x6c, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c,
	0x65, 0x73, 0x42, 0x0c, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_profile_proto_rawDescOnce sync.Once
	file_profile_proto_rawDescData = file_profile_proto_rawDesc
)

func file_profile_proto_rawDescGZIP() []byte {
	file_profile_proto_rawDescOnce.Do(func() {
		file_profile_proto_rawDescData = protoimpl.X.CompressGZIP(file_profile_proto_rawDescData)
	})
	return file_profile_proto_rawDescData
}

var file_profile_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_profile_proto_goTypes = []interface{}{
	(*Profile)(nil),   // 0: perftools.profiles.Profile
	(*ValueType)(nil), // 1: perftools.profiles.ValueType
	(*Sample)(nil),    // 2: perftools.profiles.Sample
	(*Label)(nil),     // 3: perftools.profiles.Label
	(*Mapping)(nil),   // 4: perftools.profiles.Mapping
	(*Location)(nil),  // 5: perftools.profiles.Location
	(*Line)(nil),      // 6: perftools.profiles.Line
	(*Function)(nil),  // 7: perftools.profiles.Function
}
var file_profile_proto_depIdxs = []int32{
	1, // 0: perftools.profiles.Profile.sample_type:type_name -> perftools.profiles.ValueType
	2, // 1: perftools.profiles.Profile.sample:type_name -> perftools.profiles.Sample
	4, // 2: perftools.profiles.Profile.mapping:type_name -> perftools.profiles.Mapping
	5, // 3: perftools.profiles.Profile.location:type_name -> perftools.profiles.Location
	7, // 4: perftools.profiles.Profile.function:type_name -> perftools.profiles.Function
	1, // 5: perftools.profiles.Profile.period_type:type_name -> perftools.profiles.ValueType
	3, // 6: perftools.profiles.Sample.label:type_name -> perftools.profiles.Label
	6, // 7: perftools.profiles.Location.line:type_name -> perftools.profiles.Line
	8, // [8:8] is the sub-list for method output_type
	8, // [8:8] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_profile_proto_init() }
func file_profile_proto_init() {
	if File_profile_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_profile_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Profile); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ValueType); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Sample); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Label); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Mapping); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Location); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Line); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_profile_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Function); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_profile_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_profile_proto_goTypes,
		DependencyIndexes: file_profile_proto_depIdxs,
		MessageInfos:      file_profile_proto_msgTypes,
	}.Build()
	File_profile_proto = out.File
	file_profile_proto_rawDesc = nil
	file_profile_proto_goTypes = nil
	file_profile_proto_depIdxs = nil
}

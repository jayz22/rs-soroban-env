(module
  (type (;0;) (func (param i64 i64) (result i64)))
  (type (;1;) (func (param i64 i64 i64) (result i64)))
  (type (;2;) (func (param i64 i64 i64 i64) (result i64)))
  (type (;3;) (func (result i64)))
  (type (;4;) (func (param i64) (result i64)))
  (type (;5;) (func))
  (type (;6;) (func (param i32 i32)))
  (import "m" "9" (func (;0;) (type 1)))
  (import "m" "a" (func (;1;) (type 2)))
  (import "i" "y" (func (;2;) (type 0)))
  (import "l" "_" (func (;3;) (type 1)))
  (import "l" "0" (func (;4;) (type 0)))
  (import "l" "1" (func (;5;) (type 0)))
  (func (;6;) (type 3) (result i64)
    (local i32 i64)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 0
    global.set 0
    local.get 0
    i32.const 1048608
    call 9
    local.get 0
    i64.load
    i32.wrap_i64
    if  ;; label = @1
      unreachable
    end
    local.get 0
    i64.load offset=8
    local.get 0
    i32.const 16
    i32.add
    global.set 0)
  (func (;7;) (type 4) (param i64) (result i64)
    (local i32 i32 i32 i32 i32 i32 i64 i64)
    local.get 0
    i64.const 255
    i64.and
    i64.const 4
    i64.ne
    if  ;; label = @1
      unreachable
    end
    global.get 0
    i32.const 48
    i32.sub
    local.tee 2
    global.set 0
    local.get 2
    i32.const 16
    i32.add
    local.set 4
    global.get 0
    i32.const 32
    i32.sub
    local.tee 6
    global.set 0
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          call 6
          local.tee 7
          i64.const 2
          call 4
          i64.const 1
          i64.ne
          if  ;; label = @4
            local.get 4
            i64.const 0
            i64.store
            br 1 (;@3;)
          end
          local.get 6
          local.get 7
          i64.const 2
          call 5
          i64.store
          local.get 6
          i32.const 8
          i32.add
          local.set 1
          global.get 0
          i32.const 32
          i32.sub
          local.tee 5
          global.set 0
          i32.const 1048576
          i64.load
          local.set 7
          loop  ;; label = @4
            local.get 3
            i32.const 16
            i32.ne
            if  ;; label = @5
              local.get 5
              i32.const 16
              i32.add
              local.get 3
              i32.add
              local.get 7
              i64.store
              local.get 3
              i32.const 8
              i32.add
              local.set 3
              br 1 (;@4;)
            end
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 6
              i64.load
              local.tee 7
              i64.const 255
              i64.and
              i64.const 76
              i64.eq
              if  ;; label = @6
                local.get 7
                i64.const 4503668346847236
                local.get 5
                i32.const 16
                i32.add
                i64.extend_i32_u
                i64.const 32
                i64.shl
                i64.const 4
                i64.or
                i64.const 8589934596
                call 1
                drop
                local.get 5
                i64.load offset=16
                local.tee 8
                i64.const 255
                i64.and
                i64.const 4
                i64.ne
                br_if 1 (;@5;)
                local.get 5
                local.get 5
                i32.const 24
                i32.add
                i64.load
                local.tee 7
                i32.wrap_i64
                i32.const 255
                i32.and
                local.tee 3
                i32.const 13
                i32.eq
                local.get 3
                i32.const 71
                i32.eq
                i32.or
                local.tee 3
                if (result i64)  ;; label = @7
                  local.get 7
                else
                  i64.const 0
                end
                i64.store offset=8
                local.get 5
                local.get 3
                i32.eqz
                i64.extend_i32_u
                i64.store
                local.get 5
                i64.load
                i32.wrap_i64
                i32.eqz
                if  ;; label = @7
                  local.get 5
                  i64.load offset=8
                  local.set 7
                  local.get 1
                  i64.const 0
                  i64.store
                  local.get 1
                  i32.const 16
                  i32.add
                  local.get 8
                  i64.const 32
                  i64.shr_u
                  i64.store32
                  local.get 1
                  local.get 7
                  i64.store offset=8
                  br 3 (;@4;)
                end
                local.get 1
                i64.const 1
                i64.store
                br 2 (;@4;)
              end
              local.get 1
              i64.const 1
              i64.store
              br 1 (;@4;)
            end
            local.get 1
            i64.const 1
            i64.store
          end
          local.get 5
          i32.const 32
          i32.add
          global.set 0
          local.get 6
          i64.load offset=8
          i64.eqz
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          i64.load offset=16
          local.set 7
          local.get 4
          i32.const 16
          i32.add
          local.get 6
          i32.const 24
          i32.add
          i32.load
          i32.store
          local.get 4
          local.get 7
          i64.store offset=8
          local.get 4
          i64.const 1
          i64.store
        end
        local.get 6
        i32.const 32
        i32.add
        global.set 0
        br 1 (;@1;)
      end
      unreachable
    end
    local.get 2
    i64.load offset=16
    i64.eqz
    if  ;; label = @1
      unreachable
    end
    local.get 2
    local.get 2
    i64.load offset=24
    i64.store
    local.get 2
    local.get 2
    i32.const 32
    i32.add
    i32.load
    i32.store offset=8
    local.get 2
    i64.load
    local.get 0
    i64.const 32
    i64.shr_u
    i32.wrap_i64
    local.tee 3
    i64.extend_i32_u
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    call 2
    local.set 0
    local.get 2
    local.get 3
    i32.store offset=8
    local.get 2
    local.get 0
    i64.store
    i64.const 0
    local.set 7
    call 6
    global.get 0
    i32.const 16
    i32.sub
    local.tee 4
    global.set 0
    global.get 0
    i32.const 48
    i32.sub
    local.tee 1
    global.set 0
    local.get 1
    i32.const 16
    i32.add
    local.tee 3
    local.get 2
    i32.const 8
    i32.add
    i64.load32_u
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    i64.store offset=8
    local.get 3
    i64.const 0
    i64.store
    block (result i64)  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=16
        br_if 0 (;@2;)
        local.get 1
        i64.load offset=24
        local.set 7
        local.get 1
        local.get 2
        call 9
        local.get 1
        i64.load
        i32.wrap_i64
        br_if 0 (;@2;)
        local.get 1
        i64.load offset=8
        local.set 0
        local.get 1
        local.get 7
        i64.store offset=32
        local.get 1
        local.get 0
        i64.store offset=40
        i64.const 4503668346847236
        local.get 1
        i32.const 32
        i32.add
        i64.extend_i32_u
        i64.const 32
        i64.shl
        i64.const 4
        i64.or
        i64.const 8589934596
        call 0
        local.set 7
        i64.const 0
        br 1 (;@1;)
      end
      i64.const 1
    end
    local.set 0
    local.get 4
    local.get 7
    i64.store offset=8
    local.get 4
    local.get 0
    i64.store
    local.get 1
    i32.const 48
    i32.add
    global.set 0
    local.get 4
    i64.load
    i32.wrap_i64
    if  ;; label = @1
      unreachable
    end
    local.get 4
    i64.load offset=8
    local.get 4
    i32.const 16
    i32.add
    global.set 0
    i64.const 2
    call 3
    drop
    local.get 2
    i32.const 48
    i32.add
    global.set 0
    i64.const 2)
  (func (;8;) (type 5)
    nop)
  (func (;9;) (type 6) (param i32 i32)
    local.get 0
    local.get 1
    i64.load
    i64.store offset=8
    local.get 0
    i64.const 0
    i64.store)
  (memory (;0;) 17)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048616))
  (global (;2;) i32 (i32.const 1048624))
  (export "memory" (memory 0))
  (export "power" (func 7))
  (export "_" (func 8))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2))
  (data (;0;) (i32.const 1048576) "\02\00\00\00\00\00\00\00expvalue\08\00\10\00\03\00\00\00\0b\00\10\00\05\00\00\00\0e\d0\c7|\1e"))

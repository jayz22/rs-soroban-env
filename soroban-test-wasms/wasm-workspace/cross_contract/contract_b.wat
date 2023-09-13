(module
  (type (;0;) (func (param i64 i64) (result i64)))
  (type (;1;) (func (param i64 i64 i64) (result i64)))
  (type (;2;) (func))
  (type (;3;) (func (param i32) (result i64)))
  (import "b" "j" (func (;0;) (type 0)))
  (import "v" "g" (func (;1;) (type 0)))
  (import "d" "_" (func (;2;) (type 1)))
  (func (;3;) (type 1) (param i64 i64 i64) (result i64)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get 0
    i32.const 32
    i32.sub
    local.tee 7
    global.set 0
    local.get 7
    local.get 0
    i64.store offset=16
    local.get 7
    local.get 7
    i32.const 16
    i32.add
    i64.load
    local.tee 0
    i64.store offset=8
    local.get 7
    local.get 0
    i64.const 255
    i64.and
    i64.const 77
    i64.ne
    i64.extend_i32_u
    i64.store
    local.get 7
    i64.load
    i32.wrap_i64
    local.get 1
    i64.const 255
    i64.and
    i64.const 4
    i64.ne
    i32.or
    local.get 2
    i64.const 255
    i64.and
    i64.const 4
    i64.ne
    i32.or
    i32.eqz
    if  ;; label = @1
      local.get 7
      i64.load offset=8
      local.set 0
      global.get 0
      i32.const 96
      i32.sub
      local.tee 5
      global.set 0
      local.get 5
      local.get 2
      i64.const 32
      i64.shr_u
      i64.store32 offset=12
      local.get 5
      local.get 1
      i64.const 32
      i64.shr_u
      i64.store32 offset=8
      local.get 5
      local.get 0
      i64.store offset=16
      global.get 0
      i32.const 32
      i32.sub
      local.tee 9
      global.set 0
      local.get 9
      i32.const 3
      i32.store offset=28
      local.get 9
      i32.const 1048584
      i32.store offset=24
      local.get 9
      i32.const 8
      i32.add
      local.set 12
      i64.const 0
      local.set 0
      global.get 0
      i32.const 16
      i32.sub
      local.tee 3
      global.set 0
      local.get 9
      i32.const 24
      i32.add
      local.tee 4
      i32.load
      local.set 13
      local.get 4
      i32.load offset=4
      local.set 11
      global.get 0
      i32.const 16
      i32.sub
      local.tee 4
      global.set 0
      block  ;; label = @2
        block  ;; label = @3
          loop  ;; label = @4
            local.get 10
            local.get 11
            i32.eq
            if  ;; label = @5
              local.get 3
              i32.const 0
              i32.store
              local.get 3
              local.get 0
              i64.const 8
              i64.shl
              i64.const 14
              i64.or
              i64.store offset=8
              br 3 (;@2;)
            end
            local.get 10
            i32.const 9
            i32.eq
            br_if 1 (;@3;)
            local.get 4
            block (result i32)  ;; label = @5
              local.get 4
              block (result i64)  ;; label = @6
                i64.const 1
                local.get 10
                local.get 13
                i32.add
                i32.load8_u
                local.tee 6
                i32.const 95
                i32.eq
                br_if 0 (;@6;)
                drop
                local.get 6
                i32.const 48
                i32.sub
                i32.const 10
                i32.ge_u
                if  ;; label = @7
                  local.get 6
                  i32.const 65
                  i32.sub
                  i32.const 26
                  i32.ge_u
                  if  ;; label = @8
                    local.get 6
                    i32.const 97
                    i32.sub
                    i32.const 26
                    i32.ge_u
                    if  ;; label = @9
                      local.get 4
                      i32.const 1
                      i32.store offset=4
                      local.get 4
                      i32.const 8
                      i32.add
                      local.get 6
                      i32.store
                      i32.const 1
                      br 4 (;@5;)
                    end
                    local.get 6
                    i64.extend_i32_u
                    i64.const 59
                    i64.sub
                    br 2 (;@6;)
                  end
                  local.get 6
                  i64.extend_i32_u
                  i64.const 53
                  i64.sub
                  br 1 (;@6;)
                end
                local.get 6
                i64.extend_i32_u
                i64.const 46
                i64.sub
              end
              i64.store offset=8
              i32.const 0
            end
            i32.store
            local.get 4
            i32.load
            i32.eqz
            if  ;; label = @5
              local.get 10
              i32.const 1
              i32.add
              local.set 10
              local.get 4
              i64.load offset=8
              local.get 0
              i64.const 6
              i64.shl
              i64.or
              local.set 0
              br 1 (;@4;)
            end
          end
          local.get 3
          local.get 4
          i64.load offset=4 align=4
          i64.store offset=4 align=4
          local.get 3
          i32.const 1
          i32.store
          br 1 (;@2;)
        end
        local.get 3
        i64.const 1
        i64.store
        local.get 3
        i32.const 8
        i32.add
        local.get 11
        i32.store
      end
      local.get 4
      i32.const 16
      i32.add
      global.set 0
      local.get 12
      block (result i64)  ;; label = @2
        local.get 3
        i32.load
        i32.eqz
        if  ;; label = @3
          local.get 3
          i64.load offset=8
          br 1 (;@2;)
        end
        local.get 13
        i64.extend_i32_u
        i64.const 32
        i64.shl
        i64.const 4
        i64.or
        local.get 11
        i64.extend_i32_u
        i64.const 32
        i64.shl
        i64.const 4
        i64.or
        call 0
      end
      i64.store offset=8
      local.get 12
      i64.const 0
      i64.store
      local.get 3
      i32.const 16
      i32.add
      global.set 0
      local.get 9
      i64.load offset=16
      local.set 0
      local.get 9
      i32.const 32
      i32.add
      global.set 0
      local.get 5
      local.get 0
      i64.store offset=24
      local.get 5
      i32.const 8
      i32.add
      call 5
      local.set 0
      local.get 5
      local.get 5
      i32.const 12
      i32.add
      call 5
      i64.store offset=40
      local.get 5
      local.get 0
      i64.store offset=32
      i32.const 1048576
      i64.load
      local.set 0
      loop  ;; label = @2
        local.get 8
        i32.const 16
        i32.ne
        if  ;; label = @3
          local.get 5
          i32.const 48
          i32.add
          local.get 8
          i32.add
          local.get 0
          i64.store
          local.get 8
          i32.const 8
          i32.add
          local.set 8
          br 1 (;@2;)
        end
      end
      local.get 5
      i32.const 68
      i32.add
      local.tee 3
      i32.const 0
      i32.store offset=16
      local.get 3
      local.get 5
      i32.const 32
      i32.add
      local.tee 8
      i32.store offset=8
      local.get 3
      local.get 5
      i32.const -64
      i32.sub
      local.tee 6
      i32.store offset=4
      local.get 3
      local.get 5
      i32.const 48
      i32.add
      local.tee 4
      i32.store
      local.get 3
      i32.const 12
      i32.add
      local.get 4
      i32.store
      local.get 3
      local.get 6
      local.get 4
      i32.sub
      i32.const 3
      i32.shr_u
      local.tee 6
      i32.store offset=24
      local.get 3
      local.get 6
      local.get 4
      local.get 8
      i32.sub
      i32.const 3
      i32.shr_u
      local.tee 3
      local.get 3
      local.get 6
      i32.gt_u
      select
      i32.store offset=20
      i32.const 0
      local.get 5
      i32.load offset=88
      local.tee 3
      local.get 5
      i32.load offset=84
      local.tee 4
      i32.sub
      local.tee 6
      local.get 3
      local.get 6
      i32.lt_u
      select
      local.set 8
      local.get 4
      i32.const 3
      i32.shl
      local.tee 4
      local.get 5
      i32.load offset=68
      i32.add
      local.set 3
      local.get 5
      i32.load offset=76
      local.get 4
      i32.add
      local.set 4
      loop  ;; label = @2
        local.get 8
        if  ;; label = @3
          local.get 3
          local.get 4
          i64.load
          i64.store
          local.get 8
          i32.const 1
          i32.sub
          local.set 8
          local.get 3
          i32.const 8
          i32.add
          local.set 3
          local.get 4
          i32.const 8
          i32.add
          local.set 4
          br 1 (;@2;)
        end
      end
      local.get 5
      i32.const 48
      i32.add
      i64.extend_i32_u
      i64.const 32
      i64.shl
      i64.const 4
      i64.or
      i64.const 8589934596
      call 1
      local.set 0
      local.get 5
      i32.const 16
      i32.add
      i64.load
      local.get 5
      i32.const 24
      i32.add
      i64.load
      local.get 0
      call 2
      local.tee 0
      i64.const 255
      i64.and
      i64.const 4
      i64.ne
      if  ;; label = @2
        unreachable
      end
      local.get 5
      i32.const 96
      i32.add
      global.set 0
      local.get 7
      local.get 0
      i64.const 32
      i64.shr_u
      i64.store32 offset=24
      local.get 7
      i32.const 24
      i32.add
      call 5
      local.get 7
      i32.const 32
      i32.add
      global.set 0
      return
    end
    unreachable)
  (func (;4;) (type 2)
    nop)
  (func (;5;) (type 3) (param i32) (result i64)
    (local i32 i64)
    global.get 0
    i32.const 16
    i32.sub
    local.tee 1
    global.set 0
    local.get 1
    local.get 0
    i64.load32_u
    i64.const 32
    i64.shl
    i64.const 4
    i64.or
    i64.store offset=8
    local.get 1
    i64.const 0
    i64.store
    local.get 1
    i64.load offset=8
    local.get 1
    i32.const 16
    i32.add
    global.set 0)
  (memory (;0;) 17)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048587))
  (global (;2;) i32 (i32.const 1048592))
  (export "memory" (memory 0))
  (export "add_with" (func 3))
  (export "_" (func 4))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2))
  (data (;0;) (i32.const 1048576) "\02\00\00\00\00\00\00\00add"))

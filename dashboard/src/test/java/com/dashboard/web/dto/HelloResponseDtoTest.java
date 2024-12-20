package com.dashboard.web.dto;


import com.dashboard.web.dto.HelloResponseDto;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class HelloResponseDtoTest {

    @Test
    public void 롬복_기능_테스트() {
        //given
        String name = "test";
        int amount = 1000;

        //when
        HelloResponseDto dto = new HelloResponseDto(name, amount);

        //then
        assertThat(dto.getName()).isEqualTo(name); //assertj라는 테스트 검증 라이브러리의 검증 메소드입니다.
        assertThat(dto.getAmount()).isEqualTo(amount);
    }
}

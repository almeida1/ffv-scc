package com.fatec.scc;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.junit4.SpringRunner;

import com.fatec.scc.controller.HomeController;

@RunWith(SpringRunner.class)
@WebMvcTest(HomeController.class)
class HomeControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@Test
	public void testHomePage() throws Exception {
		mockMvc.perform(get("/"))
		.andExpect(status().isOk())
		.andExpect(view().name("paginaMenu"));
	}
	@Test
	public void testCadastrarCliente() throws Exception {
		mockMvc.perform(get("/clientes"))
		.andExpect(status().isOk())
		.andExpect(view().name("cadastrarCliente"));
	}
	@Test
	public void testCadastrarEndereco() throws Exception {
		mockMvc.perform(get("/fornecedores"))
		.andExpect(status().isOk())
		.andExpect(view().name("cadastrarFornecedor"));
	}
}
